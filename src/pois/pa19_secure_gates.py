from __future__ import annotations

import secrets

from .pa18_ot import ot_receiver_step1, ot_receiver_step2, ot_sender_step


def secure_and(params, a: int, b: int) -> int:
    pk0, pk1, st = ot_receiver_step1(params, b)
    c0, c1 = ot_sender_step(pk0, pk1, 0, a)
    return ot_receiver_step2(st, c0, c1) & 1


def secure_xor(a: int, b: int) -> int:
    return (a ^ b) & 1


def secure_not(a: int) -> int:
    return a ^ 1


def truth_table(params) -> list[tuple[int, int, int, int]]:
    rows = []
    for a in (0, 1):
        for b in (0, 1):
            rows.append((a, b, secure_and(params, a, b), secure_xor(a, b)))
    return rows
