from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from collections import Counter

from primostrata_edge import PrimoSearch, PrimoStore


def bench_store_vs_sqlite():
    print("\n=== 1. PrimoStore64 (CubePoint64 WAL) vs SQLite WAL ===")
    with tempfile.TemporaryDirectory() as d:
        wal_path = os.path.join(d, "primo.wal")
        db_path = os.path.join(d, "sqlite.db")

        # --- Crash recovery verification (torn-tail simulation) ---
        with PrimoStore(wal_path, durable_sync=False) as s:
            for i in range(1000):
                s.put(f"k:{i}", f"order-payload-{i}")
            s.flush()
        raw = open(wal_path, "rb").read()
        with open(wal_path, "wb") as f:
            f.write(raw[:-20])  # Simulate power loss mid-frame
        with PrimoStore(wal_path, durable_sync=False) as s2:
            seq, rec = s2.stats()
            assert rec == 999, f"Expected 999 recovered intact records, got {rec}"
            assert s2.get("k:998") == b"order-payload-998"
            assert s2.get("k:999") is None
        print(f"  [Crash Recovery PASS] Simulated torn tail -> Fail-Closed recovered {rec}/1000 intact CubePoint64 frames")

        # --- Write / Atomic Decrement / Read throughput ---
        sql = sqlite3.connect(db_path, isolation_level=None)
        sql.execute("PRAGMA journal_mode=WAL")
        sql.execute("PRAGMA synchronous=NORMAL")
        sql.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v BLOB)")
        sql.execute("CREATE TABLE stock (id TEXT PRIMARY KEY, qty INTEGER)")
        sql.execute("INSERT INTO stock VALUES ('concert:1', 100000)")

        n_ops = 10_000
        # SQLite buffered KV writes (with BEGIN/COMMIT per write like realistic API)
        t0 = time.perf_counter()
        for i in range(n_ops):
            sql.execute("BEGIN IMMEDIATE")
            sql.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (f"o:{i}", b'{"id":1,"qty":2}'))
            sql.execute("COMMIT")
        sql_put_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        for i in range(n_ops):
            sql.execute("BEGIN IMMEDIATE")
            r = sql.execute("SELECT qty FROM stock WHERE id='concert:1'").fetchone()
            sql.execute("UPDATE stock SET qty = ? WHERE id='concert:1'", (r[0] - 1,))
            sql.execute("COMMIT")
        sql_decr_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        for i in range(n_ops):
            _ = sql.execute("SELECT v FROM kv WHERE k=?", (f"o:{i}",)).fetchone()
        sql_get_s = time.perf_counter() - t0
        sql.close()

        wal2 = os.path.join(d, "bench.wal")
        with PrimoStore(wal2, durable_sync=False) as ps:
            t0 = time.perf_counter()
            for i in range(n_ops):
                ps.put(f"o:{i}", b'{"id":1,"qty":2}')
            ps.flush()
            ps_put_s = time.perf_counter() - t0

            t0 = time.perf_counter()
            for i in range(n_ops):
                ok, rem = ps.decr_if_ge("concert:1", 1, init_if_missing=100_000)
                assert ok
            ps.flush()
            ps_decr_s = time.perf_counter() - t0
            assert rem == 90_000

            t0 = time.perf_counter()
            for i in range(n_ops):
                _ = ps.get(f"o:{i}")
            ps_get_s = time.perf_counter() - t0

        print(f"  SQLite WAL ({n_ops:,} txn put/decr/get)   | put {n_ops/sql_put_s:>9,.0f}/s | decr {n_ops/sql_decr_s:>9,.0f}/s | get {n_ops/sql_get_s:>9,.0f}/s")
        print(f"  PrimoStore64 ({n_ops:,} WAL put/decr/get) | put {n_ops/ps_put_s:>9,.0f}/s | decr {n_ops/ps_decr_s:>9,.0f}/s | get {n_ops/ps_get_s:>9,.0f}/s")


def bench_alx_search_vs_fts5():
    print("\n=== 2. PrimoSearch (ALX-24 Phonetic + VEC31) vs SQLite FTS5 vs Pure Python (5,000 docs) ===")
    cities = ["Almaty Arena", "Astana Congress Hall", "Shymkent Dome", "Tashkent Palace", "Bishkek Hall"]
    genres = ["Synthwave Neon Tour", "Symphony Classics", "Cyber Rock Live", "Jazz Night Acoustic", "Electronic Pulse"]

    docs = []
    for i in range(5_000):
        txt = f"{genres[i % len(genres)]} in {cities[i % len(cities)]} VIP pass seat row {i % 40} special {i}"
        docs.append((i + 1, txt))

    # Build SQLite FTS5
    sql = sqlite3.connect(":memory:")
    sql.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(id UNINDEXED, body)")
    t0 = time.perf_counter()
    sql.executemany("INSERT INTO docs_fts (id, body) VALUES (?, ?)", docs)
    fts_build_ms = (time.perf_counter() - t0) * 1000

    # Build Pure Python inverted index
    t0 = time.perf_counter()
    py_inv: dict[str, list[int]] = {}
    for did, txt in docs:
        for tok in txt.lower().split():
            py_inv.setdefault(tok, []).append(did)
    py_build_ms = (time.perf_counter() - t0) * 1000

    # Build PrimoSearch (ALX-24)
    ps = PrimoSearch()
    t0 = time.perf_counter()
    for did, txt in docs:
        ps.add_doc(did, txt)
    alx_build_ms = (time.perf_counter() - t0) * 1000

    # Cross-script phonetic check (Cyrillic query matching Latin docs!)
    cross_hits = ps.query("Алматы синтвейв арена", top_k=5)
    fts_cross = sql.execute("SELECT id FROM docs_fts WHERE docs_fts MATCH 'Алматы' LIMIT 5").fetchall()
    assert len(cross_hits) > 0 and (cross_hits[0][0] - 1) % 5 == 0, f"Unexpected cross-script top hit: {cross_hits}"
    print(f"  [Cross-Script ALX PASS] Query 'Алматы синтвейв арена' -> top doc_id={cross_hits[0][0]} ('{docs[cross_hits[0][0]-1][1][:45]}...') | SQLite FTS5 hits={len(fts_cross)}")

    queries = ["Synthwave Almaty VIP", "Rock Astana seat", "Jazz Bishkek acoustic", "Symphony Tashkent pass", "Electronic Shymkent neon"] * 200
    t0 = time.perf_counter()
    for q in queries:
        _ = sql.execute("SELECT id FROM docs_fts WHERE docs_fts MATCH ? LIMIT 10", (q,)).fetchall()
    fts_qps = len(queries) / (time.perf_counter() - t0)

    t0 = time.perf_counter()
    for q in queries:
        c = Counter()
        for tok in q.lower().split():
            for did in py_inv.get(tok, ()):
                c[did] += 1
        _ = c.most_common(10)
    py_qps = len(queries) / (time.perf_counter() - t0)

    t0 = time.perf_counter()
    for q in queries:
        _ = ps.query(q, top_k=10)
    alx_qps = len(queries) / (time.perf_counter() - t0)

    print(f"  SQLite FTS5 ({len(docs):,} docs, build {fts_build_ms:>5.1f} ms) | query {fts_qps:>8,.0f} qps")
    print(f"  Pure Python ({len(docs):,} docs, build {py_build_ms:>5.1f} ms) | query {py_qps:>8,.0f} qps")
    print(f"  PrimoSearch ({len(docs):,} docs, build {alx_build_ms:>5.1f} ms) | query {alx_qps:>8,.0f} qps (+cross-script +VEC31)")
    ps.close()
    sql.close()


if __name__ == "__main__":
    bench_store_vs_sqlite()
    bench_alx_search_vs_fts5()
