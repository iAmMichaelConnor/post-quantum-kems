#!/usr/bin/env bash
# lattice_kem_core's shared keygen/encapsulate/decapsulate take a `legacy`
# selector that switches the transform and disables the ML-KEM key-hash check.
# A witness-valued selector would let a prover choose, so those functions must
# stay private. This compiles small consumer packages with `nargo check`:
# the scheme-named entry points must resolve and the flagged ones must not.
set -eu

NARGO=${NARGO:-nargo}
core="$(cd "$(dirname "$0")/../noir/lattice_kem_core" && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

check() { # check <name> <main.nr source>; prints nargo's stderr, returns its status
    mkdir -p "$scratch/$1/src"
    printf '[package]\nname = "%s"\ntype = "bin"\nauthors = [""]\n\n[dependencies]\nlattice_kem_core = { path = "%s" }\n' \
        "$1" "$core" > "$scratch/$1/Nargo.toml"
    printf '%s\n' "$2" > "$scratch/$1/src/main.nr"
    (cd "$scratch/$1" && "$NARGO" check 2>&1 >/dev/null)
}

named='fn main(d: [u8; 32], z: [u8; 32], dk: [u8; 1632], ct: [u8; 768]) -> pub [u8; 32] {
    let (pk, _) = lattice_kem_core::kem::mlkem_keygen::<2>(d, z);
    let _ = lattice_kem_core::kem::kyber_keygen::<2>(d, z);
    let (_, a) = lattice_kem_core::kem::mlkem_encapsulate::<2>(pk, z);
    let (_, b) = lattice_kem_core::kem::kyber_encapsulate::<2>(pk, z);
    let c = lattice_kem_core::kem::mlkem_decapsulate::<2>(dk, ct);
    let e = lattice_kem_core::kem::kyber_decapsulate::<2>(dk, ct);
    let (_, f) = lattice_kem_core::kem::mlkem_decapsulate_from_seeds::<2>(d, z, ct);
    let (_, g) = lattice_kem_core::kem::kyber_decapsulate_from_seeds::<2>(d, z, ct);
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i] ^ c[i] ^ e[i] ^ f[i] ^ g[i];
    }
    out
}'
if ! output=$(check named "$named"); then
    echo "scheme-named entry points failed to resolve:" >&2
    echo "$output" >&2
    exit 1
fi

# The KEM layer takes the scheme selector; the K-PKE layer takes it (keygen)
# and the strict-decoding flag (encrypt).
flagged=(
    'kem_keygen|fn main(d: [u8; 32], z: [u8; 32], legacy: bool) -> pub [u8; 800] { lattice_kem_core::kem::keygen::<2>(d, z, legacy).0 }'
    'kem_encapsulate|fn main(pk: [u8; 800], e: [u8; 32], legacy: bool) -> pub [u8; 32] { lattice_kem_core::kem::encapsulate::<2>(pk, e, legacy).1 }'
    'kem_decapsulate|fn main(dk: [u8; 1632], ct: [u8; 768], legacy: bool) -> pub [u8; 32] { lattice_kem_core::kem::decapsulate::<2>(dk, ct, legacy) }'
    'pke_keygen|fn main(d: [u8; 32], legacy: bool) -> pub [u8; 800] { lattice_kem_core::pke::keygen::<2>(d, legacy).0 }'
    'pke_encrypt|fn main(pk: [u8; 800], m: [u8; 32], c: [u8; 32], strict: bool) -> pub [u8; 768] { lattice_kem_core::pke::encrypt::<2>(pk, m, c, strict) }'
)
for entry in "${flagged[@]}"; do
    name=${entry%%|*}
    if output=$(check "$name" "${entry#*|}"); then
        echo "$name: a flagged function is callable from outside lattice_kem_core" >&2
        exit 1
    fi
    if ! grep -q private <<< "$output"; then
        echo "$name: rejected for a reason other than visibility:" >&2
        echo "$output" >&2
        exit 1
    fi
done
echo "lattice_kem_core visibility: ok"
