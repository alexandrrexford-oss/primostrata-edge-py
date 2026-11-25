from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_pool_lock = threading.Lock()
_conns_by_tid: Dict[Tuple[str, int], sqlite3.Connection] = {}
_write_lock = threading.Lock()

SEED_CONCERTS = [
    (1, "Synthwave Arena Tour", "Almaty Arena", "2026-12-12 20:00", 120, 200_000, "Awesome acoustics!<script>alert('xss_comment')</script>"),
    (2, "Zero-Float Live", "Astana Congress Hall", "2026-12-19 19:30", 95, 200_000, "Best show of the year!"),
    (3, "Midnight Neon Fest", "Almaty Central", "2026-12-26 21:00", 150, 200_000, "VIP lounge worth it<script>fetch('//evil.example')</script>"),
]


def init_db(db_path: str) -> None:
    if os.path.exists(db_path):
        os.remove(db_path)
    for ext in ("-wal", "-shm"):
        if os.path.exists(db_path + ext):
            os.remove(db_path + ext)
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """
            CREATE TABLE concerts (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                venue TEXT NOT NULL,
                event_date TEXT NOT NULL,
                price INTEGER NOT NULL,
                initial_seats INTEGER NOT NULL,
                remaining_seats INTEGER NOT NULL,
                featured_review TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                concert_id INTEGER NOT NULL,
                buyer_name TEXT NOT NULL,
                qty INTEGER NOT NULL,
                total_price INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO concerts (id, title, venue, event_date, price, initial_seats, remaining_seats, featured_review)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(cid, t, v, d, p, s, s, rev) for (cid, t, v, d, p, s, rev) in SEED_CONCERTS],
        )
        conn.commit()
    finally:
        conn.close()


def _conn(db_path: str) -> sqlite3.Connection:
    key = (db_path, threading.get_native_id())
    c = _conns_by_tid.get(key)
    if c is None:
        c = sqlite3.connect(db_path, timeout=10.0, isolation_level=None, check_same_thread=False)
        c.execute("PRAGMA busy_timeout=5000")
        c.execute("PRAGMA synchronous=NORMAL")
        with _pool_lock:
            _conns_by_tid[key] = c
    return c


def list_concerts(db_path: str) -> List[Dict[str, Any]]:
    rows = _conn(db_path).execute(
        "SELECT id, title, venue, event_date, price, remaining_seats FROM concerts ORDER BY id"
    ).fetchall()
    return [
        {
            "id": r[0],
            "title": r[1],
            "venue": r[2],
            "event_date": r[3],
            "price": r[4],
            "remaining_seats": r[5],
        }
        for r in rows
    ]


def get_concert(db_path: str, cid: int) -> Optional[Dict[str, Any]]:
    r = _conn(db_path).execute(
        "SELECT id, title, venue, event_date, price, remaining_seats, featured_review FROM concerts WHERE id = ?",
        (cid,),
    ).fetchone()
    if not r:
        return None
    return {
        "id": r[0],
        "title": r[1],
        "venue": r[2],
        "event_date": r[3],
        "price": r[4],
        "remaining_seats": r[5],
        "featured_review": r[6],
    }


def create_order(db_path: str, concert_id: int, buyer_name: str, qty: int) -> Tuple[int, Dict[str, Any]]:
    if qty <= 0 or qty > 10:
        return 400, {"detail": "qty must be between 1 and 10"}
    name = (buyer_name or "Guest").strip()[:64] or "Guest"
    with _write_lock:
        c = _conn(db_path)
        c.execute("BEGIN IMMEDIATE")
        try:
            row = c.execute(
                "SELECT price, remaining_seats FROM concerts WHERE id = ?", (concert_id,)
            ).fetchone()
            if not row:
                c.execute("ROLLBACK")
                return 404, {"detail": "Concert not found"}
            price, remaining = row
            if remaining < qty:
                c.execute("ROLLBACK")
                return 409, {"detail": "Sold out", "remaining_seats": remaining}
            new_rem = remaining - qty
            total = price * qty
            c.execute("UPDATE concerts SET remaining_seats = ? WHERE id = ?", (new_rem, concert_id))
            cur = c.execute(
                "INSERT INTO orders (concert_id, buyer_name, qty, total_price, created_at) VALUES (?, ?, ?, ?, ?)",
                (concert_id, name, qty, total, time.time()),
            )
            oid = cur.lastrowid
            c.execute("COMMIT")
            return 201, {
                "order_id": oid,
                "concert_id": concert_id,
                "buyer_name": name,
                "qty": qty,
                "total_price": total,
                "remaining_seats": new_rem,
            }
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
            raise


def get_order(db_path: str, order_id: int) -> Optional[Dict[str, Any]]:
    r = _conn(db_path).execute(
        "SELECT id, concert_id, buyer_name, qty, total_price, created_at FROM orders WHERE id = ?",
        (order_id,),
    ).fetchone()
    if not r:
        return None
    return {
        "order_id": r[0],
        "concert_id": r[1],
        "buyer_name": r[2],
        "qty": r[3],
        "total_price": r[4],
        "created_at": r[5],
    }


def audit_db(db_path: str) -> Dict[str, Any]:
    c = _conn(db_path)
    con_rows = c.execute("SELECT id, initial_seats, remaining_seats FROM concerts").fetchall()
    ord_sum = c.execute("SELECT COALESCE(SUM(qty), 0), COUNT(*) FROM orders").fetchone()
    sold_orders = int(ord_sum[0])
    order_count = int(ord_sum[1])
    total_init = sum(r[1] for r in con_rows)
    total_rem = sum(r[2] for r in con_rows)
    no_negative = all(r[2] >= 0 for r in con_rows)
    return {
        "order_count": order_count,
        "sold_tickets": sold_orders,
        "total_initial": total_init,
        "total_remaining": total_rem,
        "invariant_ok": no_negative and (sold_orders + total_rem == total_init),
    }
