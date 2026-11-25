from __future__ import annotations

import os
import tempfile

from primostrata_edge import PrimoSearch, PrimoStore


def test_primo_store_wal_and_crash_recovery():
    with tempfile.TemporaryDirectory() as d:
        wal = os.path.join(d, "test.wal")
        with PrimoStore(wal, durable_sync=False) as s:
            s.put("ticket:1", "vip-row-a")
            ok, rem = s.decr_if_ge("stock:1", 3, init_if_missing=10)
            assert ok and rem == 7
            ok2, rem2 = s.decr_if_ge("stock:1", 8)
            assert not ok2 and rem2 == 7
            s.flush()

        # Simulate torn tail frame (-6 bytes) and verify fail-closed recovery
        raw = open(wal, "rb").read()
        with open(wal, "wb") as f:
            f.write(raw[:-6])

        with PrimoStore(wal, durable_sync=False) as s2:
            assert s2.get("ticket:1") == b"vip-row-a"


def test_primo_search_exact_and_cross_script_phonetic():
    ps = PrimoSearch()
    try:
        ps.add_doc(1, "Synthwave Neon Tour in Almaty Arena VIP pass")
        ps.add_doc(2, "Classical Symphony in Astana Congress Hall")
        hits = ps.query("Алматы синтвейв арена", top_k=5)
        assert len(hits) >= 1
        assert hits[0][0] == 1
    finally:
        ps.close()
