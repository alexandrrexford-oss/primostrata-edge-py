from __future__ import annotations

import pytest

from primostrata_edge import EdgeRateLimitedError, PrimostrataEdge, WaveTicketSession


def test_contour_a_default_and_optional_contour_b():
    key = bytes(range(1, 33))
    nonce = bytes(range(10, 22))
    aad = b"session:py-99"
    pt = b"pos=(128,64);hp=100;weapon=railgun"

    with PrimostrataEdge() as edge:
        # Contour A (default): pure WaveCipher31-512 + MAC
        w_a = edge.seal_wave(key, nonce, aad, pt)
        assert edge.open_wave(key, nonce, aad, w_a) == pt

        # Tamper rejected fail-closed
        bad = bytearray(w_a)
        bad[-1] ^= 0xFF
        with pytest.raises(ValueError):
            edge.open_wave(key, nonce, aad, bytes(bad))

        # Optional Contour B: WaveCipher31-256 + RFC ChaCha20-Poly1305 cascade
        w_b = edge.seal_wave(key, nonce, aad, pt, contour="b")
        assert w_b != w_a
        assert edge.open_wave(key, nonce, aad, w_b, contour="b") == pt


def test_wave_ticket_session_replay_and_budget():
    root = b"\x5A" * 32
    aad = b"room:7"
    with WaveTicketSession(root, epoch_id=3, max_tickets=3, rounds=4) as tx, \
         WaveTicketSession(root, epoch_id=3, max_tickets=3, rounds=4) as rx:
        t0 = tx.seal_next(aad, b"pkt-0")
        t1 = tx.seal_next(aad, b"pkt-1")
        # Out-of-order UDP delivery passes
        assert rx.open(aad, t1) == b"pkt-1"
        assert rx.open(aad, t0) == b"pkt-0"
        # Replay blocked fail-closed
        with pytest.raises(EdgeRateLimitedError):
            rx.open(aad, t0)
        # Consume 3rd ticket and exceed budget
        t2 = tx.seal_next(aad, b"pkt-2")
        assert rx.open(aad, t2) == b"pkt-2"
        with pytest.raises(EdgeRateLimitedError):
            tx.seal_next(aad, b"pkt-3")
