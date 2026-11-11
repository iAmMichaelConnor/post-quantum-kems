// One FIPS 202 sponge serves every hash; lengths and rates specialize at compile time.
pub use fips202::{g, h, shake128, shake256, sponge};
pub fn join<let N: u32, let M: u32>(a: [u8; N], b: [u8; M]) -> [u8; N + M] {
    let mut out = [0; N + M];
    for i in 0..N {
        out[i] = a[i];
    }
    for i in 0..M {
        out[N + i] = b[i];
    }
    out
}
pub fn part<let N: u32, let M: u32>(a: [u8; N], start: u32) -> [u8; M] {
    let mut out = [0; M];
    for i in 0..M {
        out[i] = a[start + i];
    }
    out
}

// Injective little-endian packing: each sum is at most 2^64-1, below the
// native modulus. These adapters do not change a digest's byte order.
pub fn pack_words<let N: u32>(bytes: [u8; 8 * N]) -> [u64; N] {
    let mut out = [0u64; N];
    for i in 0..N {
        let mut w = 0 as Field;
        for j in 0..8 {
            w += bytes[8 * i + j] as Field * (1u64 << ((8 * j) as u64)) as Field;
        }
        // Bytes are in [0,255], so the sum is in [0,2^64-1].
        // Refine before casting; no valid byte vector is excluded.
        w.assert_max_bit_size::<64>();
        out[i] = w as u64;
    }
    out
}
pub fn unpack_words<let N: u32>(words: [u64; N]) -> [u8; 8 * N] {
    let mut out = [0u8; 8 * N];
    for i in 0..N {
        let bytes = (words[i] as Field).to_le_bytes::<8>();
        for j in 0..8 {
            out[8 * i + j] = bytes[j];
        }
    }
    out
}

fn packing_boundaries() {
    for value in [0u8, 255u8] {
        let words = pack_words::<2>(std::hint::black_box([value; 16]));
        let expected = if value == 0 {
            0u64
        } else {
            18446744073709551615u64
        };
        assert(words == [expected; 2]);
    }
    let bytes = std::hint::black_box([0u8, 1, 2, 3, 4, 5, 6, 7]);
    assert(pack_words::<1>(bytes) == [506097522914230528u64]);
}
#[test]
fn constrained_packing_boundaries() {
    packing_boundaries();
}
#[test]
unconstrained fn hint_packing_boundaries() {
    packing_boundaries();
}
