#!/usr/bin/env python3
"""Deterministic, independent kyber-py vectors for noir/ml_kem and noir/kyber
(src/vectors.nr): Brillig reference tests plus one constrained known-answer
test per operation (--check compares instead). No Noir outputs are inputs."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import Outputs

root = Path(__file__).resolve().parents[1]
outputs = Outputs(__doc__)
sys.path.insert(0, str(root / "reference/kyber-py/src"))
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768
from kyber_py.kyber import Kyber512, Kyber768

D = bytes(range(32))
Z = bytes(range(31, -1, -1))
M = bytes((7 * i + 11) % 256 for i in range(32))
# A second recipient's seeds, for the seed-form decapsulation binding tests.
OTHER_D = bytes(range(64, 96))
OTHER_Z = bytes(range(127, 95, -1))


def coefficient(pk, index):
    group, half = divmod(index, 2)
    word = int.from_bytes(pk[3 * group : 3 * group + 3], "little")
    return (word >> (12 * half)) & 0xFFF


def with_coefficient(pk, index, value):
    group, half = divmod(index, 2)
    word = int.from_bytes(pk[3 * group : 3 * group + 3], "little")
    word = (word & ~(0xFFF << (12 * half))) | (value << (12 * half))
    out = bytearray(pk)
    out[3 * group : 3 * group + 3] = word.to_bytes(3, "little")
    return bytes(out)


def alias_key(pk):
    # Replace the first t_hat coefficient c <= 766 by its 12-bit alias c + 3329.
    for index in range(256 * (len(pk) - 32) // 384):
        value = coefficient(pk, index)
        if value <= 766:
            return with_coefficient(pk, index, value + 3329)
    raise AssertionError("no aliasable coefficient")


tests_by_scheme = {"ml_kem": [], "kyber": []}
for name, model, legacy, k in [
    ("mlkem512", ML_KEM_512, False, 2),
    ("mlkem768", ML_KEM_768, False, 3),
    ("kyber512", Kyber512, True, 2),
    ("kyber768", Kyber768, True, 3),
]:
    tests = tests_by_scheme["kyber" if legacy else "ml_kem"]
    if legacy:
        rng = iter([D, Z])
        model.random_bytes = lambda n: next(rng)
        pk, sk = model.keygen()
        model.random_bytes = lambda n: M
        key, ct = model.encaps(pk)
    else:
        pk, sk = model._keygen_internal(D, Z)
        key, ct = model._encaps_internal(pk, M)
    assert model.decaps(sk, ct) == key
    corrupt = bytearray(ct)
    corrupt[0] ^= 1
    fallback = model.decaps(sk, bytes(corrupt))
    zero_fallback = model.decaps(sk, bytes(len(ct)))
    assert fallback != key
    if legacy:
        rng = iter([OTHER_D, OTHER_Z])
        model.random_bytes = lambda n: next(rng)
        other_pk, _ = model.keygen()
        rng = iter([D, OTHER_Z])
        model.random_bytes = lambda n: next(rng)
        _, other_z_sk = model.keygen()
    else:
        other_pk, _ = model._keygen_internal(OTHER_D, OTHER_Z)
        _, other_z_sk = model._keygen_internal(D, OTHER_Z)
    assert other_pk != pk
    other_z_fallback = model.decaps(other_z_sk, bytes(corrupt))
    assert other_z_fallback != fallback
    extra = dict(
        other_d=OTHER_D,
        other_z=OTHER_Z,
        other_pk=other_pk,
        other_z_fallback=other_z_fallback,
    )
    if legacy:
        # Round-three Kyber decodes pk modulo q, so an alias pk is accepted, but
        # the canonical key holder derives a different key.
        alias_pk = alias_key(pk)
        model.random_bytes = lambda n: M
        alias_key_sender, alias_ct = model.encaps(alias_pk)
        alias_key_recipient = model.decaps(sk, alias_ct)
        assert alias_key_sender != alias_key_recipient
        assert alias_key_sender != key and alias_ct != ct
        extra.update(
            alias_pk=alias_pk,
            alias_ct=alias_ct,
            alias_key=alias_key_sender,
            alias_recipient_key=alias_key_recipient,
        )
    case = dict(
        d=D,
        z=Z,
        m=M,
        pk=pk,
        sk=sk,
        ct=ct,
        key=key,
        corrupt=bytes(corrupt),
        fallback=fallback,
        zero_fallback=zero_fallback,
        **extra,
    )
    for field, data in case.items():
        tests.append(
            f"global {name.upper()}_{field.upper()}: [u8; {len(data)}] = {list(data)};"
        )
    prefix = name.upper()
    flag = str(legacy).lower()
    tests.append(f"""#[test]
unconstrained fn {name}_reference() {{
    let (pk, sk) = crate::{name}::keygen({prefix}_D, {prefix}_Z);
    assert(pk == {prefix}_PK); assert(sk == {prefix}_SK);
    let (ct, key) = crate::{name}::encapsulate(pk, {prefix}_M);
    assert(ct == {prefix}_CT); assert(key == {prefix}_KEY);
    assert(crate::{name}::decapsulate(sk, ct) == key);
    assert(crate::{name}::decapsulate(sk, {prefix}_CORRUPT) == {prefix}_FALLBACK);
    assert(crate::{name}::decapsulate(sk, [0; {len(ct)}]) == {prefix}_ZERO_FALLBACK);
}}""")
    # Seed-form decapsulation binds the PKE secret to pk; z is not bound by pk.
    tests.append(f"""#[test]
unconstrained fn {name}_seed_decapsulation() {{
    let (pk, key) = crate::{name}::decapsulate_from_seeds({prefix}_D, {prefix}_Z, {prefix}_CT);
    assert(pk == {prefix}_PK); assert(key == {prefix}_KEY);
    let (pk, key) = crate::{name}::decapsulate_from_seeds({prefix}_D, {prefix}_Z, {prefix}_CORRUPT);
    assert(pk == {prefix}_PK); assert(key == {prefix}_FALLBACK);
    let (pk, key) = crate::{name}::decapsulate_from_seeds({prefix}_D, {prefix}_OTHER_Z, {prefix}_CORRUPT);
    assert(pk == {prefix}_PK); assert(key == {prefix}_OTHER_Z_FALLBACK);
}}""")
    tests.append(f"""#[test(should_fail_with = "recipient key mismatch")]
unconstrained fn {name}_seed_decapsulation_rejects_other_recipient() {{
    // A caller that binds the registered pk rejects another recipient's seeds.
    let (pk, _) = crate::{name}::decapsulate_from_seeds({prefix}_OTHER_D, {prefix}_Z, {prefix}_CT);
    assert(pk == {prefix}_OTHER_PK);
    assert(pk == {prefix}_PK, "recipient key mismatch");
}}""")
    if legacy:
        tests.append(f"""#[test]
unconstrained fn {name}_alias_key_is_not_the_recipient_key() {{
    // Kyber accepts an alias pk; the canonical key holder derives another key.
    let (ct, key) = crate::{name}::encapsulate({prefix}_ALIAS_PK, {prefix}_M);
    assert(ct == {prefix}_ALIAS_CT); assert(key == {prefix}_ALIAS_KEY);
    assert(crate::{name}::decapsulate({prefix}_SK, ct) == {prefix}_ALIAS_RECIPIENT_KEY);
    assert(key != {prefix}_ALIAS_RECIPIENT_KEY);
}}""")
    # Constrained known-answer runs of each operation. black_box keeps the
    # inputs as witnesses, so the ACIR constraints are executed, not folded.
    tests.append(f"""#[test]
fn {name}_keygen_constrained() {{
    let (pk, sk) = crate::{name}::keygen(std::hint::black_box({prefix}_D), std::hint::black_box({prefix}_Z));
    assert(pk == {prefix}_PK); assert(sk == {prefix}_SK);
}}""")
    tests.append(f"""#[test]
fn {name}_encapsulate_constrained() {{
    let (ct, key) = crate::{name}::encapsulate(std::hint::black_box({prefix}_PK), std::hint::black_box({prefix}_M));
    assert(ct == {prefix}_CT); assert(key == {prefix}_KEY);
}}""")
    tests.append(f"""#[test]
fn {name}_decapsulate_constrained() {{
    assert(crate::{name}::decapsulate(std::hint::black_box({prefix}_SK), std::hint::black_box({prefix}_CT)) == {prefix}_KEY);
}}""")
for package, tests in tests_by_scheme.items():
    outputs.add(root / "noir" / package / "src/vectors.nr", "\n".join(tests) + "\n")
outputs.finish()
