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
    send_from_directory,
    make_response,
)
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import tempfile
import uuid

import requests

from werkzeug.utils import secure_filename

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

APP_VERSION_FILE = Path(__file__).resolve().with_name("VERSION")


def _load_version():
    """Read the release version shown in the UI."""
    try:
        return APP_VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


APP_VERSION = _load_version()

# Sibling LWSG Sale Tracker app: built SPA served under /sale-tracker,
# its FastAPI backend proxied on /api, and a direct link for the dev server.
SALE_TRACKER_DIST = Path(
    os.getenv(
        "SALE_TRACKER_DIST",
        Path(__file__).resolve().parent.parent / "LWSG-Sale-Tracker" / "frontend" / "dist",
    )
)
SALE_TRACKER_API = os.getenv("SALE_TRACKER_API", "http://localhost:8000").rstrip("/")
SALE_TRACKER_DIRECT_URL = os.getenv("SALE_TRACKER_DIRECT_URL", "http://localhost:3000")


@app.context_processor
def inject_app_version():
    # Read per request so a VERSION bump shows up without a restart.
    return {"app_version": _load_version(), "sale_tracker_url": SALE_TRACKER_DIRECT_URL}


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
        return render_template(
            "dashboard.html", shop_name=None, listings=[], counts={}, counted_total=0
        )

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
        counts = _read_counts()
        counted_total = sum(
            1
            for lid in (entry.get("listing_id") for entry in all_listings)
            if f"etsy:{lid}" in counts
        )
        return render_template(
            "dashboard.html",
            shop_name=session.get("shop_name", f"Shop #{shop_id}"),
            listings=all_listings,
            total=len(all_listings),
            counts=counts,
            counted_total=counted_total,
        )
    except Exception as e:
        flash(f"Error fetching listings: {e}", "danger")
        return render_template(
            "dashboard.html",
            shop_name=session.get("shop_name"),
            listings=[],
            counts={},
            counted_total=0,
        )


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

    # Numeric fields — Etsy ignores these on PATCH, so they go through inventory
    numeric_fields = {}
    for field in ["price", "quantity"]:
        val = request.form.get(field)
        if val is not None and val.strip():
            try:
                numeric_fields[field] = float(val) if field == "price" else int(val)
            except ValueError:
                flash(f"Invalid value for {field}", "warning")

    # Handle tags as list
    if "tags" in update_fields and isinstance(update_fields["tags"], str):
        update_fields["tags"] = [t.strip() for t in update_fields["tags"].split(",") if t.strip()]

    if not update_fields and not numeric_fields:
        flash("No fields to update.", "warning")
        return redirect(url_for("listing_detail", listing_id=listing_id))

    try:
        shop_id = session.get("shop_id")
        note = None
        if update_fields:
            client.update_listing(listing_id, shop_id=shop_id, **update_fields)
        if numeric_fields:
            result = client.set_listing_price_quantity(listing_id, **numeric_fields)
            if isinstance(result, dict):
                note = result.get("note")
        save_client_tokens(client)
        flash(f"Listing #{listing_id} updated successfully!", "success")
        if note:
            flash(f"Listing #{listing_id}: {note}", "warning")
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


@app.route("/sku-generator", defaults={"asset_path": ""})
@app.route("/sku-generator/<path:asset_path>")
@login_required
def sku_generator(asset_path):
    """Serve the standalone SKU generator inside the authenticated Etsy app."""
    generator_root = Path(__file__).resolve().parent.parent / "SKU Code Generator"
    if not generator_root.is_dir():
        flash("SKU Generator folder is not available on this machine.", "warning")
        return redirect(url_for("dashboard"))

    relative_path = asset_path or "sku-generator.html"
    if relative_path == "sku-generator.html":
        # Keep all root-absolute assets and print-logo references within the app.
        html = (generator_root / relative_path).read_text(encoding="utf-8")
        html = html.replace('href="/"', 'href="/dashboard"')
        html = html.replace('src="/logo.png"', 'src="/sku-generator/logo.png"')
        html = html.replace("const HEADER_LOGO_PNG = '/logo.png';", "const HEADER_LOGO_PNG = '/sku-generator/logo.png';")
        html = html.replace("new URL('/logo.png', window.location.origin)", "new URL('/sku-generator/logo.png', window.location.origin)")

        # The external generator keeps its original UI and local settings, while
        # shared SKU history is loaded/saved through this authenticated app.
        history_json = json.dumps(_read_sku_history(), ensure_ascii=False).replace("<", "\\u003c")
        html = html.replace(
            '<script>',
            '<script>window.__SHARED_SKU_HISTORY__ = ' + history_json + '; </script>\n<script>',
            1,
        )
        old_save = """    function saveToLocalStorage() {
      try {
        localStorage.setItem('texstyls-generated-skus-v2', JSON.stringify(skuHistory));
      } catch (err) {
        console.warn('Could not save to localStorage:', err);
      }
    }"""
        new_save = """    let sharedSaveTimer = null;
    function saveToLocalStorage() {
      try {
        const data = JSON.stringify(skuHistory);
        localStorage.setItem('texstyls-generated-skus-v2', data);
        clearTimeout(sharedSaveTimer);
        sharedSaveTimer = setTimeout(() => {
          fetch('/api/sku-history', {
            method: 'PUT',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: data
          }).then(response => {
            if (!response.ok) throw new Error('Shared history save failed');
            showSyncStatus('active', 'Shared history synced');
          }).catch(() => showSyncStatus('error', 'Shared history save failed'));
        }, 350);
      } catch (err) {
        console.warn('Could not save SKU history:', err);
      }
    }"""
        if old_save not in html:
            app.logger.error("External SKU generator changed: local history save hook not found")
            return "SKU Generator integration needs an update.", 500
        html = html.replace(old_save, new_save, 1)
        html = html.replace(
            "      // Restore sync from the persisted handle — no file picker needed when the\n      // browser still grants permission",
            "      // Merge shared history from the Etsy app with this browser's local history.\n      mergeSKUs(window.__SHARED_SKU_HISTORY__);\n      saveToLocalStorage();\n\n      // Shared history is synced through the authenticated Etsy app API.",
            1,
        )
        # Suppress the standalone generator's optional file-picker sync setup;
        # the app now provides shared history across browsers and devices.
        sync_start = html.find("      const syncEnabled = localStorage.getItem(SYNC_STORAGE_KEY);", html.find("async function init()"))
        sync_end = html.find("      updateHistoryDisplay();", sync_start)
        if sync_start < 0 or sync_end < 0:
            app.logger.error("External SKU generator changed: sync initialization block not found")
            return "SKU Generator integration needs an update.", 500
        html = html[:sync_start] + "      showSyncStatus('active', 'Shared history synced with this app');\n      document.getElementById('syncBanner').classList.remove('show');\n\n" + html[sync_end:]
        html = html.replace(
            "          localStorage.removeItem('texstyls-generated-skus-v2');\n          localStorage.removeItem('texstyls-generated-skus');\n        } catch (err) {}\n        updateHistoryDisplay();",
            "          localStorage.removeItem('texstyls-generated-skus-v2');\n          localStorage.removeItem('texstyls-generated-skus');\n        } catch (err) {}\n        saveToLocalStorage();\n        updateHistoryDisplay();",
            1,
        )
        old_remove = """    // Shared-history deletion — replaced by the Etsy app integration, which
    // also removes the codes from the shared server history. No-op standalone.
    function removeSharedHistoryEntries(codes) {
      return Promise.resolve();
    }"""
        new_remove = """    function removeSharedHistoryEntries(codes) {
      const all = !Array.isArray(codes) || codes.length === 0;
      const requests = all
        ? [fetch('/api/sku-history', { method: 'DELETE', credentials: 'same-origin' })]
        : codes.map(code => fetch('/api/sku-history/' + encodeURIComponent(code), {
            method: 'DELETE', credentials: 'same-origin'
          }));
      return Promise.all(requests).then(responses => {
        if (responses.some(r => !r.ok)) throw new Error('Shared history delete failed');
        showSyncStatus('active', 'Shared history synced');
      }).catch(() => showSyncStatus('error', 'Shared history delete failed'));
    }"""
        if old_remove not in html:
            app.logger.error("External SKU generator changed: shared history delete hook not found")
            return "SKU Generator integration needs an update.", 500
        html = html.replace(old_remove, new_remove, 1)
        response = make_response(html)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        response.headers["Cache-Control"] = "no-store"
        return response

    # Only expose the generator logo; do not make its history JSON or source
    # files downloadable through the asset route.
    if asset_path != "logo.png":
        return "Not found", 404
    response = make_response(send_from_directory(generator_root, "logo.png"))
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


# ---- LWSG Sale Tracker (built SPA served from the sibling project) ----


@app.route("/sale-tracker")
@app.route("/sale-tracker/<path:asset_path>")
@login_required
def sale_tracker(asset_path=""):
    """Serve the Sale Tracker SPA under this app's origin."""
    root = SALE_TRACKER_DIST.resolve()
    if not root.is_dir():
        flash(
            'Sale Tracker build not found. Run: cd "LWSG-Sale-Tracker/frontend" '
            "&& npm run build:embed",
            "warning",
        )
        return redirect(url_for("dashboard"))

    if asset_path:
        candidate = (root / asset_path).resolve()
        if candidate.is_file() and candidate.is_relative_to(root):
            return send_from_directory(root, asset_path)

    # Unknown path → hand it to the SPA router (history fallback).
    return send_from_directory(root, "index.html")


@app.route("/api/<path:api_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@login_required
def proxy_sale_tracker_api(api_path):
    """Forward Sale Tracker API calls to its FastAPI backend.

    This app's own /api routes are literal paths, so they win the routing;
    anything else belongs to the Sale Tracker.
    """
    url = f"{SALE_TRACKER_API}/api/{api_path}"
    method = request.method
    headers = {"Content-Type": request.content_type} if request.content_type else {}
    try:
        upstream = requests.request(
            method,
            url,
            params=request.args,
            data=request.get_data() if method not in ("GET", "HEAD") else None,
            headers=headers,
            timeout=60,
        )
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": (
                f"Sale Tracker backend is not reachable at {SALE_TRACKER_API} ({e}). "
                "Start it with: cd LWSG-Sale-Tracker && .venv/bin/uvicorn backend.app:app --port 8000"
            )
        }), 502

    hop_by_hop = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    response = make_response(upstream.content, upstream.status_code)
    for key, value in upstream.raw.headers.items():
        if key.lower() not in hop_by_hop:
            response.headers[key] = value
    return response


# Persist the standalone generator's shared SKU-history file beside its source.
SKU_HISTORY_FILE = Path(__file__).resolve().parent.parent / "SKU Code Generator" / "texstyls-sku-history.json"
SKU_HISTORY_LOCK = threading.Lock()


def _read_sku_history():
    try:
        data = json.loads(SKU_HISTORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _entry_timestamp(entry):
    """Best-effort modification time for a history entry."""
    try:
        return int(entry.get("timestamp") or 0)
    except (TypeError, ValueError):
        return 0


def _merge_history_entries(existing, incoming):
    """Union two history lists keyed by SKU code.

    Entries already on disk are always kept; incoming entries only replace an
    existing code when they are newer, so a sync from one computer can never
    wipe out work saved from another. Returns (merged, added, updated).
    """
    merged = {}
    order = []
    for entry in existing:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("code", "")).strip().upper()
        if key and key not in merged:
            merged[key] = entry
            order.append(key)

    added = updated = 0
    for entry in incoming:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("code", "")).strip().upper()
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = entry
            order.append(key)
            added += 1
        elif entry != current and _entry_timestamp(entry) > _entry_timestamp(current):
            merged[key] = entry
            updated += 1
    return [merged[key] for key in order], added, updated


def _write_sku_history(history):
    """Atomically replace the shared history file. Caller must hold SKU_HISTORY_LOCK."""
    SKU_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=".sku-history-", suffix=".tmp", dir=SKU_HISTORY_FILE.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            json.dump(history, temp_file, ensure_ascii=False, indent=2)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, SKU_HISTORY_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


@app.route("/api/sku-history", methods=["GET", "PUT"])
@login_required
def api_sku_history():
    """Read or save shared SKU history for the embedded generator."""
    if request.method == "GET":
        return jsonify(_read_sku_history())

    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON array"}), 400

    try:
        with SKU_HISTORY_LOCK:
            # Merge instead of overwrite: a computer with a stale local copy
            # must not delete entries another computer has already saved.
            history, added, updated = _merge_history_entries(_read_sku_history(), data)
            _write_sku_history(history)
    except OSError:
        app.logger.exception("Unable to save shared SKU history")
        return jsonify({"error": "Could not save SKU history"}), 500
    return jsonify({"saved": len(history), "added": added, "updated": updated, "merged": True})


@app.route("/api/sku-history", methods=["DELETE"])
@login_required
def api_sku_history_clear():
    """Wipe the shared history — used by the generator's clear-all action."""
    try:
        with SKU_HISTORY_LOCK:
            _write_sku_history([])
    except OSError:
        app.logger.exception("Unable to clear shared SKU history")
        return jsonify({"error": "Could not clear SKU history"}), 500
    return jsonify({"saved": 0})


@app.route("/api/sku-history/<path:code>", methods=["DELETE"])
@login_required
def api_sku_history_delete(code):
    """Remove one SKU code from the shared history (per-row trash button)."""
    key = str(code).strip().upper()
    if not key:
        return jsonify({"error": "Missing SKU code"}), 400
    with SKU_HISTORY_LOCK:
        history = _read_sku_history()
        kept = [
            entry for entry in history
            if isinstance(entry, dict)
            and str(entry.get("code", "")).strip().upper() != key
        ]
        removed = len(history) - len(kept)
        if removed:
            try:
                _write_sku_history(kept)
            except OSError:
                app.logger.exception("Unable to delete SKU from shared history")
                return jsonify({"error": "Could not delete SKU"}), 500
    return jsonify({"removed": removed, "saved": len(kept)})


@app.route("/api/sku-history/import", methods=["POST"])
@login_required
def api_sku_history_import():
    """Merge an uploaded history export with the shared history, preserving unique SKUs."""
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a JSON history file"}), 400
    if Path(secure_filename(uploaded.filename)).suffix.lower() != ".json":
        return jsonify({"error": "Only JSON files are supported"}), 400
    try:
        incoming = json.loads(uploaded.read().decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "That file is not valid JSON"}), 400
    if not isinstance(incoming, list):
        return jsonify({"error": "Expected a JSON array"}), 400

    with SKU_HISTORY_LOCK:
        history = _read_sku_history()
        seen = {str(entry.get("code", "")).strip().upper() for entry in history if isinstance(entry, dict)}
        added = 0
        for entry in incoming:
            if not isinstance(entry, dict):
                continue
            code = str(entry.get("code", "")).strip().upper()
            if code and code not in seen:
                history.append(entry)
                seen.add(code)
                added += 1
        try:
            SKU_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".sku-history-", suffix=".tmp", dir=SKU_HISTORY_FILE.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                    json.dump(history, temp_file, ensure_ascii=False, indent=2)
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                os.replace(temp_name, SKU_HISTORY_FILE)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        except OSError:
            app.logger.exception("Unable to merge shared SKU history")
            return jsonify({"error": "Could not save SKU history"}), 500
    return jsonify({"added": added, "total": len(history)})


# ─── Inventory count marks ───
# One JSON file holds every "counted" tick, shared with the Sale Tracker, so
# the Etsy dashboard and the tracker's inventory page always agree — and
# either app still works when the other isn't running.

INVENTORY_COUNTS_FILE = Path(
    os.getenv(
        "INVENTORY_COUNTS_FILE",
        Path(__file__).resolve().parent.parent / "SKU Code Generator" / "texstyls-inventory-counts.json",
    )
)
INVENTORY_COUNTS_LOCK = threading.Lock()


def _read_counts():
    """Return {key: counted_at} from the shared counts file."""
    try:
        data = json.loads(INVENTORY_COUNTS_FILE.read_text(encoding="utf-8"))
        counts = data.get("counts", {})
        return counts if isinstance(counts, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_counts(counts):
    """Atomically persist the counts map. Call inside INVENTORY_COUNTS_LOCK."""
    INVENTORY_COUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": counts,
    }
    fd, temp_name = tempfile.mkstemp(
        prefix=".counts-", suffix=".tmp", dir=INVENTORY_COUNTS_FILE.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            json.dump(payload, temp_file, ensure_ascii=False, indent=2)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, INVENTORY_COUNTS_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


@app.route("/api/inventory-counts", methods=["GET", "POST"])
@login_required
def api_inventory_counts():
    """Read or update the shared counted marks (etsy:<listing_id>, item:<id>)."""
    if request.method == "GET":
        return jsonify(_read_counts())

    body = request.get_json(silent=True) or {}
    key = str(body.get("key", "")).strip()
    if not key:
        return jsonify({"error": "Missing key"}), 400
    counted = bool(body.get("counted"))

    with INVENTORY_COUNTS_LOCK:
        counts = _read_counts()
        if counted:
            counts[key] = datetime.now().isoformat(timespec="seconds")
        else:
            counts.pop(key, None)
        try:
            _write_counts(counts)
        except OSError:
            app.logger.exception("Unable to save inventory counts")
            return jsonify({"error": "Could not save counts"}), 500
    return jsonify(counts)


@app.route("/api/inventory-counts/reset", methods=["POST"])
@login_required
def api_inventory_counts_reset():
    """Clear every counted mark for a new inventory count."""
    with INVENTORY_COUNTS_LOCK:
        try:
            _write_counts({})
        except OSError:
            app.logger.exception("Unable to reset inventory counts")
            return jsonify({"error": "Could not reset counts"}), 500
    return jsonify({"counts": {}, "reset": True})


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

        # Price and quantity live on the listing's inventory, not on PATCH
        raw_value = value.strip()
        numeric_value = None
        if field in ("price", "quantity"):
            try:
                numeric_value = float(raw_value) if field == "price" else int(raw_value)
            except ValueError:
                flash(f"Please enter a valid number for {field}.", "warning")
                return redirect(url_for("bulk_update"))
            if numeric_value < 0:
                flash(f"{field} cannot be negative.", "warning")
                return redirect(url_for("bulk_update"))

        for lid in selected_ids:
            try:
                if field in ("price", "quantity"):
                    client.set_listing_price_quantity(int(lid), **{field: numeric_value})
                else:
                    client.update_listing(int(lid), shop_id=shop_id, **{field: raw_value})
                results["success"].append(lid)
            except Exception as e:
                results["failed"].append({"id": lid, "error": str(e)})

        save_client_tokens(client)
        return render_template("bulk_results.html", results=results, field=field, value=value)

    # GET — show listings to select for bulk update
    try:
        data = client.get_listings_by_shop(shop_id, limit=100, offset=0)
        listings = data.get("results", [])
        # Deactivated listings drop out of the table on their own (Etsy only
        # returns active ones by default) — fetch them separately so they can
        # be revealed and put back later.
        deactivated = []
        try:
            resp = client.get_listings_by_shop(shop_id, limit=100, offset=0, state="inactive")
            deactivated = resp.get("results", [])
        except Exception:
            app.logger.warning("Could not fetch deactivated listings", exc_info=True)
        save_client_tokens(client)
        return render_template(
            "bulk_update.html",
            listings=listings,
            deactivated=deactivated,
            counts=_read_counts(),
        )
    except Exception as e:
        flash(f"Error fetching listings: {e}", "danger")
        return redirect(url_for("dashboard"))


@app.route("/listing/<int:listing_id>/reactivate", methods=["POST"])
@login_required
def reactivate_listing(listing_id):
    """Put a deactivated listing back on Etsy (state → active)."""
    client = get_client()
    if not client:
        return redirect(url_for("index"))
    try:
        client.update_listing(listing_id, shop_id=session.get("shop_id"), state="active")
        save_client_tokens(client)
        flash("Listing is active again on Etsy.", "success")
    except Exception as e:
        flash(f"Could not reactivate listing: {e}", "danger")
    return redirect(url_for("bulk_update"))


if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
