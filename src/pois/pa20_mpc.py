from __future__ import annotations

from dataclasses import dataclass

from .pa19_secure_gates import secure_and, secure_not, secure_xor


@dataclass
class Gate:
    op: str
    a: int
    b: int | None


@dataclass
class Circuit:
    n_inputs: int
    gates: list[Gate]
    outputs: list[int]

    def eval_plain(self, inputs: list[int]) -> list[int]:
        wires = list(inputs)
        for g in self.gates:
            if g.op == "XOR":
                wires.append(wires[g.a] ^ wires[g.b])
            elif g.op == "AND":
                wires.append(wires[g.a] & wires[g.b])
            elif g.op == "NOT":
                wires.append(wires[g.a] ^ 1)
            else:
                raise ValueError("unknown gate")
        return [wires[i] for i in self.outputs]


def secure_eval(params, circuit: Circuit, x_alice: list[int], y_bob: list[int]) -> list[int]:
    wires = list(x_alice + y_bob)
    for g in circuit.gates:
        if g.op == "XOR":
            wires.append(secure_xor(wires[g.a], wires[g.b]))
        elif g.op == "AND":
            wires.append(secure_and(params, wires[g.a], wires[g.b]))
        elif g.op == "NOT":
            wires.append(secure_not(wires[g.a]))
        else:
            raise ValueError("unknown gate")
    return [wires[i] for i in circuit.outputs]


def equality_circuit(n: int) -> Circuit:
    gates: list[Gate] = []
    # inputs: x[0..n-1], y[0..n-1]
    xor_wires = []
    base = 2 * n
    for i in range(n):
        gates.append(Gate("XOR", i, n + i))
        gates.append(Gate("NOT", base + 2 * i, None))
        xor_wires.append(base + 2 * i + 1)
    cur = xor_wires[0]
    idx = base + 2 * n
    for w in xor_wires[1:]:
        gates.append(Gate("AND", cur, w))
        cur = idx
        idx += 1
    return Circuit(n_inputs=2 * n, gates=gates, outputs=[cur])


def _or_gate(gates: list[Gate], u: int, v: int, next_idx: int) -> tuple[int, int]:
    # OR(u,v) = u xor v xor (u and v)
    gates.append(Gate("XOR", u, v))
    x = next_idx
    next_idx += 1
    gates.append(Gate("AND", u, v))
    a = next_idx
    next_idx += 1
    gates.append(Gate("XOR", x, a))
    o = next_idx
    next_idx += 1
    return o, next_idx


def add_circuit(n: int) -> Circuit:
    gates: list[Gate] = []
    idx = 2 * n
    # const zero from x0 xor x0
    gates.append(Gate("XOR", 0, 0))
    carry = idx
    idx += 1
    sums: list[int] = []

    for i in range(n):
        xi = i
        yi = n + i
        gates.append(Gate("XOR", xi, yi))
        axb = idx
        idx += 1
        gates.append(Gate("XOR", axb, carry))
        s = idx
        idx += 1
        sums.append(s)

        gates.append(Gate("AND", xi, yi))
        t1 = idx
        idx += 1
        gates.append(Gate("AND", axb, carry))
        t2 = idx
        idx += 1
        carry, idx = _or_gate(gates, t1, t2, idx)

    return Circuit(n_inputs=2 * n, gates=gates, outputs=sums)


def millionaire_circuit(n: int) -> Circuit:
    gates: list[Gate] = []
    idx = 2 * n
    # gt = 0, eq = 1
    gates.append(Gate("XOR", 0, 0))
    gt = idx
    idx += 1
    gates.append(Gate("NOT", gt, None))
    eq = idx
    idx += 1

    for i in range(n - 1, -1, -1):
        xi = i
        yi = n + i
        gates.append(Gate("NOT", yi, None))
        not_y = idx
        idx += 1
        gates.append(Gate("AND", xi, not_y))
        x_and_noty = idx
        idx += 1
        gates.append(Gate("AND", eq, x_and_noty))
        term = idx
        idx += 1
        gt, idx = _or_gate(gates, gt, term, idx)

        gates.append(Gate("XOR", xi, yi))
        x_xor_y = idx
        idx += 1
        gates.append(Gate("NOT", x_xor_y, None))
        bit_eq = idx
        idx += 1
        gates.append(Gate("AND", eq, bit_eq))
        eq = idx
        idx += 1

    return Circuit(n_inputs=2 * n, gates=gates, outputs=[gt])


def int_to_bits(x: int, n: int) -> list[int]:
    return [(x >> i) & 1 for i in range(n)]


def bits_to_int(bits: list[int]) -> int:
    v = 0
    for i, b in enumerate(bits):
        v |= (b & 1) << i
    return v


def secure_millionaire(params, x: int, y: int, n: int = 8) -> int:
    c = millionaire_circuit(n)
    out = secure_eval(params, c, int_to_bits(x, n), int_to_bits(y, n))
    return out[0]


def secure_equality(params, x: int, y: int, n: int = 8) -> int:
    c = equality_circuit(n)
    out = secure_eval(params, c, int_to_bits(x, n), int_to_bits(y, n))
    return out[0]


def secure_addition(params, x: int, y: int, n: int = 8) -> int:
    c = add_circuit(n)
    out = secure_eval(params, c, int_to_bits(x, n), int_to_bits(y, n))
    return bits_to_int(out)
