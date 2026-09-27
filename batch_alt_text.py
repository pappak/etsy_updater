"""
Batch set alt text on all images for all listings.
Downloads each image, re-uploads with descriptive alt text.
"""
import json
import os
import time
import requests
from etsy_client import EtsyClient

client = EtsyClient(os.getenv("ETSY_API_KEYSTRING"), os.getenv("ETSY_SHARED_SECRET"))
with open(".tokens.json") as f:
    tokens = json.load(f)
client.access_token = tokens["access_token"]
client.refresh_token = tokens.get("refresh_token")
client.token_expiry = tokens.get("token_expiry", 0)

SHOP_ID = 14727921

# ---- Alt text templates by product type ----
# Keyed by SKU prefix or product type keywords
def get_alt_texts(listing, num_images):
    """Generate alt text for each image of a listing."""
    title = listing.get("title", "")
    skus = listing.get("skus", [])
    sku = skus[0] if skus else ""
    materials = listing.get("materials", [])
    material_str = ", ".join(materials) if materials else "cotton"

    title_lower = title.lower()

    # Determine product type
    if "towel" in title_lower and "set" in title_lower:
        product = "handwoven cotton towel set"
        specifics = ["folded on counter", "texture and weave close up", "draped on counter",
                     "stacked together", "hanging on oven handle", "folded detail",
                     "on wooden table", "weave and fringe detail", "with kitchen decor",
                     "rolled and stacked"]
    elif "towel" in title_lower or "dish" in title_lower or "tea" in title_lower:
        product = "handwoven cotton towel"
        specifics = ["folded on surface", "close up of weave", "draped over edge",
                     "folded detail", "hanging display", "flat lay",
                     "on kitchen counter", "weave detail", "with decor styling",
                     "rolled presentation"]
    elif "blanket" in title_lower:
        product = "handwoven cotton baby blanket"
        specifics = ["spread flat", "close up of twill weave", "folded on surface",
                     "draped over arm", "rolled detail", "corner detail",
                     "with natural light", "stripe pattern close up", "gift presentation",
                     "fabric texture detail"]
    elif "scarf" in title_lower:
        product = "handwoven scarf"
        specifics = ["draped flat", "weave detail close up", "folded on surface",
                     "draped over shoulder", "pattern detail", "fringe detail",
                     "with natural light", "fabric texture", "rolled presentation",
                     "styled with outfit"]
    elif "pillow" in title_lower or "cushion" in title_lower:
        product = "handwoven pillow"
        specifics = ["on sofa", "weave detail close up", "corner detail",
                     "styled on chair", "pattern close up", "side view",
                     "with decor", "fabric texture", "back view", "gift styling"]
    elif "napkin" in title_lower or "table" in title_lower:
        product = "handwoven table napkin"
        specifics = ["folded on table", "weave detail close up", "place setting",
                     "stacked pile", "folded detail", "flat lay",
                     "with tableware", "fabric texture", "gift presentation",
                     "corner detail"]
    elif "vest" in title_lower or "jacket" in title_lower:
        product = "handwoven vest"
        specifics = ["flat lay front", "weave detail close up", "lining detail",
                     "flat lay back", "button detail", "styled on hanger",
                     "fabric texture", "shoulder detail", "with outfit", "folded"]
    elif "bag" in title_lower or "handbag" in title_lower or "purse" in title_lower:
        product = "handwoven handbag"
        specifics = ["front view", "weave detail close up", "side view",
                     "interior pockets", "strap detail", "back view",
                     "with outfit", "bottom detail", "open view", "handle detail"]
    elif "bread" in title_lower or "bag" in title_lower:
        product = "handwoven bread bag"
        specifics = ["front view", "weave detail close up", "open showing interior",
                     "side view", "with bread inside", "drawstring detail",
                     "hanging display", "fabric texture", "folded flat", "gift styling"]
    else:
        product = "handwoven item"
        specifics = ["front view", "detail close up", "alternate angle",
                     "folded view", "detail shot", "texture close up",
                     "styled display", "craft detail", "alternate view",
                     "gift presentation"]

    descriptions = []
    for i in range(num_images):
        if i < len(specifics):
            desc = f"{product} — {specifics[i]}, {material_str}"
        else:
            desc = f"{product} — {specifics[i % len(specifics)]}, {material_str}"
        # Truncate if needed (Etsy max alt text is likely generous but keep it clean)
        if len(desc) > 250:
            desc = desc[:250]
        descriptions.append(desc)

    return descriptions


# ---- Main loop ----
all_listings = []
offset = 0
while True:
    data = client.get_listings_by_shop(SHOP_ID, limit=100, offset=offset)
    results = data.get("results", [])
    all_listings.extend(results)
    count = data.get("count", 0)
    if offset + 100 >= count:
        break
    offset += 100

print(f"Found {len(all_listings)} listings")

headers = client._headers()
headers.pop("Content-Type", None)

success = 0
failed = 0
skipped = 0

for listing in all_listings:
    lid = listing["listing_id"]
    title = listing.get("title", "Untitled")
    skus = listing.get("skus", [])
    sku = skus[0] if skus else "N/A"

    print(f"\n  [{lid}] {sku} — {title[:50]}...")

    # Get images
    try:
        images_data = client.get_listing_images(lid)
        images = images_data.get("results", [])
    except Exception as e:
        print(f"    FAILED to get images: {e}")
        failed += 1
        continue

    if not images:
        print(f"    No images found")
        skipped += 1
        continue

    # Check if alt text already exists
    already_done = all(img.get("alt_text") for img in images)
    if already_done:
        print(f"    All {len(images)} images already have alt text, skipping")
        skipped += 1
        continue

    alt_texts = get_alt_texts(listing, len(images))

    for i, img in enumerate(images):
        image_id = img["listing_image_id"]
        img_url = img["url_fullxfull"]
        alt = alt_texts[i]

        # Skip if already has alt text
        if img.get("alt_text"):
            continue

        try:
            # Download original image
            resp = requests.get(img_url, timeout=30)
            if resp.status_code != 200:
                print(f"    Image {i+1}: download failed ({resp.status_code})")
                failed += 1
                continue

            # Re-upload with alt text
            upload_url = f"https://openapi.etsy.com/v3/application/shops/{SHOP_ID}/listings/{lid}/images"
            files = {"image": ("image.jpg", resp.content, "image/jpeg")}
            data = {"alt_text": alt, "listing_image_id": image_id}

            r = requests.post(upload_url, headers=headers, files=files, data=data, timeout=60)
            if r.status_code in (200, 201):
                success += 1
            else:
                print(f"    Image {i+1}: {r.status_code} {r.text[:100]}")
                failed += 1

            # Small delay to avoid rate limiting
            time.sleep(0.5)

        except Exception as e:
            print(f"    Image {i+1}: error — {e}")
            failed += 1

    print(f"    Done — {len(images)} images processed")

print(f"\n\nComplete! {success} images updated, {failed} failed, {skipped} skipped")