"""
Etsy Listing Manager — Flask Web App
"""
import os
import json
import time
import secrets
from functools import wraps

from flask import (
    Flask,
    session,
    redirect,
    request,
    render_template,
    jsonify,
    url_for,
    flash,
)
from datetime import datetime

from dotenv import load_dotenv

from etsy_client import (
    EtsyClient,
    generate_pkce_pair,
    get_authorization_url,
    exchange_code_for_token,
)
from stats_db import init_db, record_snapshot, get_snapshots, get_all_latest_snapshots, get_daily_views

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# Ensure local stats DB is ready
init_db()


@app.template_filter("timestamp_to_date")
def timestamp_to_date(ts):
    """Convert Unix timestamp to readable date string."""
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")

ETSY_KEYSTRING = os.getenv("ETSY_API_KEYSTRING")
ETSY_SHARED_SECRET = os.getenv("ETSY_SHARED_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/oauth/callback")

# Scopes needed for full listing management
SCOPES = [
    "listings_r",
    "listings_w",
    "listings_d",
    "transactions_r",
    "transactions_w",
    "shops_r",
    "shops_w",
    "billing_r",
    "profile_r",
    "profile_w",
    "address_r",
    "address_w",
]

TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".tokens.json")


def save_tokens_to_disk(access_token, refresh_token, token_expiry, shop_id=None,
                        shop_name=None, user_name=None, user_id=None):
    """Persist tokens to disk so the user only authorizes once."""
    data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_expiry": token_expiry,
        "shop_id": shop_id,
        "shop_name": shop_name,
        "user_name": user_name,
        "user_id": user_id,
    }
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[WARN] Could not save tokens to disk: {e}")


def load_tokens_from_disk():
    """Load persisted tokens from disk, if present."""
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        with open(TOKEN_FILE) as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load tokens from disk: {e}")
        return None


def hydrate_session_from_disk():
    """If session has no token but disk does, restore it."""
    if "access_token" in session:
        return
    data = load_tokens_from_disk()
    if data and data.get("access_token"):
        session["access_token"] = data["access_token"]
        session["refresh_token"] = data.get("refresh_token")
        session["token_expiry"] = data.get("token_expiry", 0)
        session["shop_id"] = data.get("shop_id")
        session["shop_name"] = data.get("shop_name")
        session["user_name"] = data.get("user_name")
        session["user_id"] = data.get("user_id")
        session.modified = True


@app.before_request
def _restore_tokens():
    """Restore tokens from disk on each request if session is empty."""
    hydrate_session_from_disk()


def get_client():
    """Get EtsyClient from session data."""
    if "access_token" not in session:
        return None
    return EtsyClient(
        keystring=ETSY_KEYSTRING,
        shared_secret=ETSY_SHARED_SECRET,
        access_token=session.get("access_token"),
        refresh_token=session.get("refresh_token"),
        token_expiry=session.get("token_expiry", 0),
    )


def save_client_tokens(client):
    """Save tokens back to session and disk after refresh."""
    session["access_token"] = client.access_token
    session["refresh_token"] = client.refresh_token
    session["token_expiry"] = client.token_expiry
    session.modified = True
    save_tokens_to_disk(
        client.access_token, client.refresh_token, client.token_expiry,
        shop_id=session.get("shop_id"), shop_name=session.get("shop_name"),
        user_name=session.get("user_name"), user_id=session.get("user_id"),
    )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "access_token" not in session:
            flash("Please sign in with Etsy first.", "warning")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


# ---- Routes ----

@app.route("/")
def index():
    """Landing page."""
    return render_template("index.html", authenticated="access_token" in session)


@app.route("/login")
def login():
    """Start OAuth flow."""
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_hex(32)

    # Store in session for the callback
    session["code_verifier"] = code_verifier
    session["oauth_state"] = state
    session.modified = True

    auth_url = get_authorization_url(
        ETSY_KEYSTRING, REDIRECT_URI, SCOPES, code_challenge, state
    )
    return redirect(auth_url)


@app.route("/oauth/callback")
def oauth_callback():
    """Handle OAuth callback from Etsy."""
    error = request.args.get("error")
    if error:
        flash(f"Etsy authorization error: {error}", "danger")
        return redirect(url_for("index"))

    code = request.args.get("code")
    state = request.args.get("state")
    stored_state = session.pop("oauth_state", None)
    code_verifier = session.pop("code_verifier", None)

    if not code or not code_verifier:
        flash("Missing authorization code or verifier. Please try again.", "danger")
        return redirect(url_for("index"))

    if state != stored_state:
        flash("State mismatch. Possible CSRF attack.", "danger")
        return redirect(url_for("index"))

    try:
        token_data = exchange_code_for_token(
            ETSY_KEYSTRING, ETSY_SHARED_SECRET, REDIRECT_URI, code, code_verifier
        )
    except Exception as e:
        flash(f"Failed to exchange code for token: {e}", "danger")
        return redirect(url_for("index"))

    session["access_token"] = token_data["access_token"]
    session["refresh_token"] = token_data.get("refresh_token")
    session["token_expiry"] = time.time() + token_data["expires_in"]
    session.modified = True

    # Fetch shop info (getUser needs email_r scope we don't request, so skip it)
    client = get_client()
    session["user_id"] = session.get("access_token", "").split(".")[0]
    try:
        shops_data = client.get_shops_for_user()
        # This endpoint may return a single Shop object or a paginated list
        shop = None
        if isinstance(shops_data, dict):
            if "results" in shops_data and shops_data["results"]:
                shop = shops_data["results"][0]
            elif "shop_id" in shops_data:
                shop = shops_data
        if shop:
            session["shop_id"] = shop["shop_id"]
            session["shop_name"] = shop.get("shop_name", f"Shop #{shop['shop_id']}")
            session["user_name"] = shop.get("shop_name", "Etsy User")
    except Exception as e:
        flash(f"Logged in, but couldn't fetch shop info: {e}", "warning")

    # Persist everything to disk so re-auth isn't needed next time
    save_tokens_to_disk(
        session.get("access_token"), session.get("refresh_token"),
        session.get("token_expiry"), shop_id=session.get("shop_id"),
        shop_name=session.get("shop_name"), user_name=session.get("user_name"),
        user_id=session.get("user_id"),
    )

    flash("Successfully connected to Etsy!", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    """Clear session and persisted tokens."""
    session.clear()
    try:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
    except Exception as e:
        print(f"[WARN] Could not remove token file: {e}")
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard showing all listings."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    shop_id = session.get("shop_id")
    if not shop_id:
        # Fallback: try to fetch shop now (e.g. if callback fetch failed)
        try:
            shops_data = client.get_shops_for_user()
            shop = None
            if isinstance(shops_data, dict):
                if "results" in shops_data and shops_data["results"]:
                    shop = shops_data["results"][0]
                elif "shop_id" in shops_data:
                    shop = shops_data
            if shop:
                shop_id = shop["shop_id"]
                session["shop_id"] = shop_id
                session["shop_name"] = shop.get("shop_name", f"Shop #{shop_id}")
                session.modified = True
                save_client_tokens(client)
        except Exception as e:
            flash(f"Could not fetch your shop: {e}", "danger")

    if not shop_id:
        flash("No shop found. Make sure you have an Etsy shop.", "warning")
        return render_template("dashboard.html", shop_name=None, listings=[])

    try:
        # Fetch all listings (paginated)
        all_listings = []
        offset = 0
        while True:
            data = client.get_listings_by_shop(shop_id, limit=100, offset=offset)
            results = data.get("results", [])
            all_listings.extend(results)
            count = data.get("count", 0)
            if offset + 100 >= count:
                break
            offset += 100

        save_client_tokens(client)
        return render_template(
            "dashboard.html",
            shop_name=session.get("shop_name", f"Shop #{shop_id}"),
            listings=all_listings,
            total=len(all_listings),
        )
    except Exception as e:
        flash(f"Error fetching listings: {e}", "danger")
        return render_template("dashboard.html", shop_name=session.get("shop_name"), listings=[])


@app.route("/listing/<int:listing_id>")
@login_required
def listing_detail(listing_id):
    """View and edit a single listing."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    try:
        listing = client.get_listing(listing_id)
        images = client.get_listing_images(listing_id)
        inventory = client.get_listing_inventory(listing_id)
        save_client_tokens(client)

        # Record today's snapshot for view-history chart
        views = listing.get("views", 0) or 0
        favorites = listing.get("num_favorers", 0) or 0
        record_snapshot(listing_id, views, favorites)
        snapshots = get_snapshots(listing_id, days=60)

        return render_template(
            "listing_detail.html",
            listing=listing,
            images=images.get("results", []),
            inventory=inventory,
            snapshots=snapshots,
        )
    except Exception as e:
        flash(f"Error fetching listing #{listing_id}: {e}", "danger")
        return redirect(url_for("dashboard"))


@app.route("/listing/<int:listing_id>/update", methods=["POST"])
@login_required
def update_listing(listing_id):
    """Update a listing's fields."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    # Collect fields that were submitted (only non-empty ones)
    update_fields = {}
    text_fields = ["title", "description", "tags", "materials", "who_made",
                   "when_made", "taxonomy_id", "shipping_profile_id",
                   "listing_type", "state", "item_weight", "item_length",
                   "item_width", "item_height", "item_weight_unit",
                   "item_dimensions_unit"]
    for field in text_fields:
        val = request.form.get(field)
        if val is not None and val.strip():
            update_fields[field] = val.strip()

    # Numeric fields
    for field in ["price", "quantity"]:
        val = request.form.get(field)
        if val is not None and val.strip():
            try:
                update_fields[field] = float(val) if field == "price" else int(val)
            except ValueError:
                flash(f"Invalid value for {field}", "warning")

    # Handle tags as list
    if "tags" in update_fields and isinstance(update_fields["tags"], str):
        update_fields["tags"] = [t.strip() for t in update_fields["tags"].split(",") if t.strip()]

    if not update_fields:
        flash("No fields to update.", "warning")
        return redirect(url_for("listing_detail", listing_id=listing_id))

    try:
        shop_id = session.get("shop_id")
        result = client.update_listing(listing_id, shop_id=shop_id, **update_fields)
        save_client_tokens(client)
        flash(f"Listing #{listing_id} updated successfully!", "success")
    except Exception as e:
        flash(f"Error updating listing #{listing_id}: {e}", "danger")

    return redirect(url_for("listing_detail", listing_id=listing_id))


@app.route("/listing/<int:listing_id>/reorder-images", methods=["POST"])
@login_required
def reorder_images(listing_id):
    """Reorder listing images based on submitted order."""
    client = get_client()
    if not client:
        return jsonify({"error": "Not authenticated"}), 401

    shop_id = session.get("shop_id")
    if not shop_id:
        return jsonify({"error": "No shop ID in session"}), 400

    data = request.get_json(silent=True) or {}
    image_ids = data.get("image_ids", [])
    if not image_ids:
        return jsonify({"error": "No image IDs provided"}), 400

    errors = []
    # Two-pass to avoid rank conflicts:
    # Pass 1 — move all to temp high ranks (100+) to clear existing positions
    for i, image_id in enumerate(image_ids):
        try:
            client.reorder_listing_image(shop_id, listing_id, image_id, 100 + i)
            time.sleep(0.3)
        except Exception as e:
            errors.append(f"Image {image_id} (temp): {e}")

    # Pass 2 — assign final ranks 1, 2, 3...
    for rank, image_id in enumerate(image_ids, start=1):
        try:
            client.reorder_listing_image(shop_id, listing_id, image_id, rank)
            time.sleep(0.3)
        except Exception as e:
            errors.append(f"Image {image_id} (final rank {rank}): {e}")

    save_client_tokens(client)
    if errors:
        return jsonify({"error": "; ".join(errors)}), 500
    return jsonify({"ok": True})


@app.route("/listing/<int:listing_id>/update-inventory", methods=["POST"])
@login_required
def update_listing_inventory(listing_id):
    """Update a listing's inventory (pricing/quantity per variant)."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    products_json = request.form.get("products_json")
    if not products_json:
        flash("No inventory data provided.", "warning")
        return redirect(url_for("listing_detail", listing_id=listing_id))

    try:
        result = client.update_listing_inventory(listing_id, products_json)
        save_client_tokens(client)
        flash(f"Inventory for listing #{listing_id} updated!", "success")
    except Exception as e:
        flash(f"Error updating inventory: {e}", "danger")

    return redirect(url_for("listing_detail", listing_id=listing_id))


@app.route("/stats")
@login_required
def stats_dashboard():
    """Shop stats dashboard — listings overview + sales/revenue."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    shop_id = session.get("shop_id")

    try:
        # All active listings
        all_listings = []
        offset = 0
        while True:
            data = client.get_listings_by_shop(shop_id, limit=100, offset=offset)
            results = data.get("results", [])
            all_listings.extend(results)
            count = data.get("count", 0)
            if offset + 100 >= count:
                break
            offset += 100

        # All receipts (orders) — full history, paginated
        all_receipts = []
        offset = 0
        while True:
            receipts_data = client.get_shop_receipts(shop_id, limit=100, offset=offset)
            results = receipts_data.get("results", [])
            all_receipts.extend(results)
            count = receipts_data.get("count", 0)
            if offset + 100 >= count:
                break
            offset += 100

        # Compute revenue metrics
        total_revenue = 0.0
        total_orders = len(all_receipts)
        monthly_revenue = {}   # "YYYY-MM" -> float
        yearly_revenue  = {}   # "YYYY"    -> float
        for r in all_receipts:
            gt = r.get("grandtotal") or r.get("grand_total") or {}
            if isinstance(gt, dict):
                amt = gt.get("amount", 0) / gt.get("divisor", 100)
            else:
                amt = 0.0
            total_revenue += amt
            ts = r.get("create_timestamp") or r.get("creation_tsz") or 0
            if ts:
                dt = datetime.fromtimestamp(ts)
                mo = dt.strftime("%Y-%m")
                yr = dt.strftime("%Y")
                monthly_revenue[mo] = monthly_revenue.get(mo, 0.0) + amt
                yearly_revenue[yr]  = yearly_revenue.get(yr, 0.0) + amt

        sorted_months = sorted(monthly_revenue.keys())
        monthly_labels = sorted_months
        monthly_values = [round(monthly_revenue[m], 2) for m in sorted_months]

        sorted_years = sorted(yearly_revenue.keys())
        yearly_labels = sorted_years
        yearly_values = [round(yearly_revenue[y], 2) for y in sorted_years]

        # Daily buckets for client-side range filtering
        daily_revenue = {}
        for r in all_receipts:
            gt = r.get("grandtotal") or r.get("grand_total") or {}
            amt = gt.get("amount", 0) / gt.get("divisor", 100) if isinstance(gt, dict) else 0.0
            ts = r.get("create_timestamp") or r.get("creation_tsz") or 0
            if ts:
                day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                daily_revenue[day] = daily_revenue.get(day, 0.0) + amt
        sorted_days = sorted(daily_revenue.keys())
        daily_labels = sorted_days
        daily_values = [round(daily_revenue[d], 2) for d in sorted_days]

        # Listings sorted by views descending
        listings_by_views = sorted(all_listings, key=lambda x: x.get("views", 0), reverse=True)

        # Daily views history from snapshots
        daily_views_data = get_daily_views(days=365)
        views_labels = [d["day"] for d in daily_views_data]
        views_values = [d["views"] for d in daily_views_data]

        # Build category tags from listing tags
        all_categories = set()
        for l in all_listings:
            for tag in l.get("tags", []):
                all_categories.add(tag.lower().strip())
        sorted_categories = sorted(all_categories)

        save_client_tokens(client)
        return render_template(
            "stats_dashboard.html",
            listings=listings_by_views,
            categories=sorted_categories,
            total_listings=len(all_listings),
            total_views=sum(l.get("views", 0) for l in all_listings),
            total_favorites=sum(l.get("num_favorers", 0) for l in all_listings),
            total_orders=total_orders,
            total_revenue=round(total_revenue, 2),
            monthly_labels=monthly_labels,
            monthly_values=monthly_values,
            yearly_labels=yearly_labels,
            yearly_values=yearly_values,
            daily_labels=daily_labels,
            daily_values=daily_values,
            views_labels=views_labels,
            views_values=views_values,
            shop_name=session.get("shop_name", ""),
        )
    except Exception as e:
        flash(f"Error loading stats: {e}", "danger")
        return redirect(url_for("dashboard"))


@app.route("/api/listing-snapshots")
@login_required
def api_listing_snapshots():
    """Return snapshot history for one or more listing IDs (comma-separated ?ids=)."""
    ids_param = request.args.get("ids", "")
    try:
        listing_ids = [int(x) for x in ids_param.split(",") if x.strip().isdigit()]
    except Exception:
        return jsonify({}), 400

    result = {}
    for lid in listing_ids:
        result[str(lid)] = get_snapshots(lid, days=90)
    return jsonify(result)


@app.route("/sku-generator")
@login_required
def sku_generator():
    """SKU code generator tool."""
    return render_template("sku_generator.html")


@app.route("/bulk-update", methods=["GET", "POST"])
@login_required
def bulk_update():
    """Bulk update multiple listings."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))

    shop_id = session.get("shop_id")

    if request.method == "POST":
        selected_ids = request.form.getlist("listing_ids")
        field = request.form.get("bulk_field")
        value = request.form.get("bulk_value")

        if not selected_ids or not field or not value:
            flash("Please select listings and provide a field to update.", "warning")
            return redirect(url_for("bulk_update"))

        results = {"success": [], "failed": []}
        shop_id = session.get("shop_id")
        for lid in selected_ids:
            try:
                client.update_listing(int(lid), shop_id=shop_id, **{field: value.strip()})
                results["success"].append(lid)
            except Exception as e:
                results["failed"].append({"id": lid, "error": str(e)})

        save_client_tokens(client)
        return render_template("bulk_results.html", results=results, field=field, value=value)

    # GET — show listings to select for bulk update
    try:
        data = client.get_listings_by_shop(shop_id, limit=100, offset=0)
        listings = data.get("results", [])
        save_client_tokens(client)
        return render_template("bulk_update.html", listings=listings)
    except Exception as e:
        flash(f"Error fetching listings: {e}", "danger")
        return redirect(url_for("dashboard"))


if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
