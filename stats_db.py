"""
Local SQLite store for periodic view/favorites snapshots.
Each time a listing detail page is loaded, a snapshot is recorded.
This builds a time-series history from nothing — values accumulate over days/weeks.
"""
import sqlite3
import os
from datetime import datetime, date

DB_PATH = os.path.join(os.path.dirname(__file__), ".stats.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS listing_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                listing_id  INTEGER NOT NULL,
                recorded_at TEXT    NOT NULL,
                views       INTEGER,
                favorites   INTEGER
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_listing_snapshots_lid
            ON listing_snapshots (listing_id, recorded_at)
        """)
        conn.commit()


def record_snapshot(listing_id: int, views: int, favorites: int):
    """
    Record a snapshot for today. Only writes one row per listing per calendar day
    — subsequent page loads on the same day update the row instead.
    """
    today = date.today().isoformat()
    with _connect() as conn:
        existing = conn.execute(
            "SELECT id FROM listing_snapshots WHERE listing_id=? AND recorded_at=?",
            (listing_id, today)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE listing_snapshots SET views=?, favorites=? WHERE id=?",
                (views, favorites, existing["id"])
            )
        else:
            conn.execute(
                "INSERT INTO listing_snapshots (listing_id, recorded_at, views, favorites) VALUES (?,?,?,?)",
                (listing_id, today, views, favorites)
            )
        conn.commit()


def get_snapshots(listing_id: int, days: int = 60):
    """Return up to `days` most recent daily snapshots for a listing, oldest first."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT recorded_at, views, favorites
            FROM listing_snapshots
            WHERE listing_id = ?
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (listing_id, days)
        ).fetchall()
    return list(reversed([dict(r) for r in rows]))


def get_all_latest_snapshots():
    """Return the most recent snapshot for every tracked listing."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT listing_id, recorded_at, views, favorites
            FROM listing_snapshots
            WHERE id IN (
                SELECT MAX(id) FROM listing_snapshots GROUP BY listing_id
            )
            ORDER BY views DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def get_daily_views(days: int = 365):
    """Return total views per day across all listings, oldest first."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT recorded_at, SUM(views) as total_views
            FROM listing_snapshots
            WHERE recorded_at >= date('now', ?)
            GROUP BY recorded_at
            ORDER BY recorded_at ASC
            """,
            (f"-{days} days",)
        ).fetchall()
    return [{"day": r["recorded_at"], "views": r["total_views"]} for r in rows]
