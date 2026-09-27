"""
Etsy API v3 Client with OAuth 2.0 + PKCE authentication.
"""
import hashlib
import base64
import os
import secrets
import time
import json
from urllib.parse import urlencode
import requests

API_BASE = "https://openapi.etsy.com/v3"


def generate_pkce_pair():
    """Generate PKCE code verifier and code challenge (S256)."""
    code_verifier = secrets.token_urlsafe(96)  # 128 chars
    sha256 = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(sha256).rstrip(b"=").decode("ascii")
    )
    return code_verifier, code_challenge


def get_authorization_url(keystring, redirect_uri, scopes, code_challenge, state):
    """Build the Etsy OAuth authorization URL."""
    params = {
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "client_id": keystring,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"https://www.etsy.com/oauth/connect?{urlencode(params)}"


def exchange_code_for_token(keystring, shared_secret, redirect_uri, code, code_verifier):
    """Exchange authorization code for access + refresh tokens."""
    url = f"{API_BASE}/public/oauth/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": keystring,
        "client_secret": shared_secret,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    resp = requests.post(url, data=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(keystring, shared_secret, refresh_token):
    """Refresh an expired access token."""
    url = f"{API_BASE}/public/oauth/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": keystring,
        "client_secret": shared_secret,
        "refresh_token": refresh_token,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    resp = requests.post(url, data=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


class EtsyClient:
    """High-level Etsy API client that handles auth and requests."""

    def __init__(self, keystring, shared_secret, access_token=None, refresh_token=None, token_expiry=0):
        self.keystring = keystring
        self.shared_secret = shared_secret
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry

    def _ensure_token(self):
        """Refresh token if expired."""
        if not self.access_token:
            raise ValueError("Not authenticated. Complete OAuth flow first.")
        if time.time() >= self.token_expiry - 60:
            if self.refresh_token:
                data = refresh_access_token(
                    self.keystring, self.shared_secret, self.refresh_token
                )
                self.access_token = data["access_token"]
                self.refresh_token = data.get("refresh_token", self.refresh_token)
                self.token_expiry = time.time() + data["expires_in"]
            else:
                raise ValueError("Token expired and no refresh token available.")

    def _headers(self):
        """Build request headers with auth."""
        self._ensure_token()
        return {
            "x-api-key": f"{self.keystring}:{self.shared_secret}",
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }

    def _get(self, path, params=None):
        """GET request to Etsy API."""
        headers = self._headers()
        url = f"{API_BASE}{path}"
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path, data):
        """PATCH request to Etsy API."""
        headers = self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        url = f"{API_BASE}{path}"
        resp = requests.patch(url, headers=headers, data=data)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, data=None, files=None):
        """POST request to Etsy API."""
        headers = self._headers()
        url = f"{API_BASE}{path}"
        if files:
            resp = requests.post(url, headers=headers, data=data, files=files)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = requests.post(url, headers=headers, data=data)
        resp.raise_for_status()
        return resp.json()

    # ---- Shop ----

    def get_shop(self, shop_id):
        """Get shop details."""
        return self._get(f"/application/shops/{shop_id}")

    def find_shop(self, shop_name):
        """Find a shop by name."""
        return self._get("/application/shops", params={"shop_name": shop_name})

    # ---- Listings ----

    def get_listings_by_shop(self, shop_id, limit=100, offset=0):
        """Get all listings for a shop."""
        return self._get(
            f"/application/shops/{shop_id}/listings",
            params={"limit": min(limit, 100), "offset": offset, "includes": "Images"},
        )

    def get_listing(self, listing_id):
        """Get a single listing by ID."""
        return self._get(f"/application/listings/{listing_id}")

    def update_listing(self, listing_id, shop_id=None, **kwargs):
        """Update a listing. Pass any updatable fields as kwargs.

        Supported: title, description, tags, price, quantity, etc.
        Requires shop_id for the correct Etsy v3 endpoint.
        """
        # Convert lists to comma-separated strings for form-encoded data
        data = {}
        for key, val in kwargs.items():
            if key == "tags" and isinstance(val, list):
                # Etsy enforces max 20 chars per tag
                trimmed = [t[:20] for t in val]
                data[key] = ",".join(trimmed)
            elif isinstance(val, list):
                data[key] = ",".join(str(v) for v in val)
            elif val is not None:
                data[key] = str(val)
        if shop_id:
            return self._patch(f"/application/shops/{shop_id}/listings/{listing_id}", data)
        return self._patch(f"/application/listings/{listing_id}", data)

    def get_listing_images(self, listing_id):
        """Get images for a listing."""
        return self._get(f"/application/listings/{listing_id}/images")

    def reorder_listing_image(self, shop_id, listing_id, image_id, rank):
        """Update the rank (position) of a listing image. Rank is 1-based."""
        return self._post(
            f"/application/shops/{shop_id}/listings/{listing_id}/images",
            data={"listing_image_id": str(image_id), "rank": str(rank), "overwrite": "true"},
        )

    def get_listing_inventory(self, listing_id):
        """Get inventory for a listing."""
        return self._get(f"/application/listings/{listing_id}/inventory")

    def update_listing_inventory(self, listing_id, products_json):
        """Update inventory (pricing/quantity per variant).

        products_json should be the JSON string matching the Etsy API format.
        """
        headers = self._headers()
        headers["Content-Type"] = "application/json"
        url = f"{API_BASE}/application/listings/{listing_id}/inventory"
        resp = requests.put(url, headers=headers, json=json.loads(products_json))
        resp.raise_for_status()
        return resp.json()

    def get_shipping_profiles(self, shop_id):
        """Get shipping profiles for a shop."""
        return self._get(f"/application/shops/{shop_id}/shipping-profiles")

    def get_user(self):
        """Get the authenticated user."""
        user_id = self.get_user_id()
        return self._get(f"/application/users/{user_id}")

    def get_user_id(self):
        """Extract the numeric user ID from the access token.

        Etsy access tokens are formatted as `<user_id>.<token>`.
        """
        if not self.access_token:
            raise ValueError("No access token available.")
        return self.access_token.split(".")[0]

    def get_shops_for_user(self):
        """Get shops owned by the authenticated user."""
        user_id = self.get_user_id()
        return self._get(f"/application/users/{user_id}/shops")

    def get_shop_receipts(self, shop_id, limit=100, offset=0, min_created=None):
        """Get shop receipts (orders). Optionally filter by min_created Unix timestamp."""
        params = f"limit={limit}&offset={offset}"
        if min_created:
            params += f"&min_created={min_created}"
        return self._get(f"/application/shops/{shop_id}/receipts?{params}")

    def get_shop_transactions(self, shop_id, limit=100, offset=0):
        """Get all shop transactions (individual line items)."""
        return self._get(
            f"/application/shops/{shop_id}/transactions?limit={limit}&offset={offset}"
        )
