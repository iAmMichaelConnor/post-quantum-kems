#!/usr/bin/env python3
"""Expand published Kyber KAT seeds with AES-256 CTR-DRBG; emit Noir tests.
Host code only supplies test entropy; the KEM under test is implemented in Noir.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import Outputs
from aes256 import encrypt_block

root = Path(__file__).resolve().parents[1]
outputs = Outputs(__doc__)
sys.path.insert(0, str(root / "reference/kyber-py/src"))
from kyber_py.kyber import Kyber512, Kyber768


class DRBG:
    def __init__(self, seed):
        self.key = bytes(32)
        self.v = 0
        self.update(seed)

    def blocks(self, n):
        out = b""
        for _ in range(n):
            self.v = (self.v + 1) % (1 << 128)
            out += encrypt_block(self.key, self.v.to_bytes(16, "big"))
        return out

    def update(self, seed):
        material = bytes(a ^ b for a, b in zip(self.blocks(3), seed))
        self.key = material[:32]
        self.v = int.from_bytes(material[32:], "big")

    def generate(self, n):
        out = self.blocks((n + 15) // 16)[:n]
        self.update(bytes(48))
        return out


s = [
    "// Published Kyber round-three KATs from the pinned reference assets.",
]
for k, model, length in [(2, Kyber512, 1632), (3, Kyber768, 2400)]:
    size = "512" if k == 2 else "768"
    path = root / f"reference/kyber-py/PQCkemKAT_{length}.rsp"
    cases = []
    for block in path.read_text().strip().split("\n\n"):
        case = dict(
            line.split(" = ", 1) for line in block.splitlines() if " = " in line
        )
        if "seed" in case:
            cases.append(case)
    for case in cases[:5]:
        drbg = DRBG(bytes.fromhex(case["seed"]))
        d, z, m = [drbg.generate(32) for _ in range(3)]
        # Check the seed-expansion helper independently against every published output.
        rng = iter([d, z])
        model.random_bytes = lambda n: next(rng)
        pk, sk = model.keygen()
        model.random_bytes = lambda n: m
        ss, ct = model.encaps(pk)
        assert all(
            out.hex().upper() == case[field]
            for field, out in [("pk", pk), ("sk", sk), ("ct", ct), ("ss", ss)]
        )
        s.append(f"#[test]\nunconstrained fn kyber_kat_{k}_{case['count']}() {{")
        s.append(f" let (pk,sk) = crate::kyber{size}::keygen({list(d)}, {list(z)});")
        s.append(f" assert(pk == {list(pk)}); assert(sk == {list(sk)});")
        s.append(f" let (ct,key) = crate::kyber{size}::encapsulate(pk, {list(m)});")
        s.append(f" assert(ct == {list(ct)}); assert(key == {list(ss)});")
        s.append(f" assert(crate::kyber{size}::decapsulate(sk,ct) == key);\n}}")
outputs.add(root / "noir/kyber/src/kyber_kats.nr", "\n".join(s) + "\n")
outputs.finish()
