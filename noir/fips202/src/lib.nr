//! FIPS 202 SHA3 and SHAKE over bytes, 64-bit lanes and 64-bit words. The rate
//! and domain suffix are compile-time generics and only FIPS 202 instances
//! compile.
// FIPS 202 sponge. The rate R (bytes) and the domain suffix D are generic
// parameters, so every instance is fixed at compile time. Only FIPS 202
// instances compile; see assert_fips202_instance.
pub fn sponge<let N: u32, let O: u32, let R: u32, let D: u32>(input: [u8; N]) -> [u8; O] {
    let mut state = absorb::<N, R, D, 0>(input);
    let mut out = [0u8; O];
    for b in 0..(O + R - 1) / R {
        for lane in 0..R / 8 {
            if b * R + lane * 8 < O {
                // The standard helper constrains all eight bytes and their packed value.
                let bytes = (state[lane] as Field).to_le_bytes::<8>();
                for j in 0..8 {
                    if b * R + lane * 8 + j < O {
                        out[b * R + lane * 8 + j] = bytes[j];
                    }
                }
            }
        }
        if (b + 1) * R < O {
            state = std::hash::keccakf1600(state);
        }
    }
    out
}
/// SHA3-256.
pub fn h<let N: u32>(x: [u8; N]) -> [u8; 32] {
    sponge::<N, 32, 136, 6>(x)
}
/// SHA3-512.
pub fn g<let N: u32>(x: [u8; N]) -> [u8; 64] {
    sponge::<N, 64, 72, 6>(x)
}
/// SHAKE128 with an O-byte output.
pub fn shake128<let N: u32, let O: u32>(x: [u8; N]) -> [u8; O] {
    sponge::<N, O, 168, 31>(x)
}
/// SHAKE256 with an O-byte output.
pub fn shake256<let N: u32, let O: u32>(x: [u8; N]) -> [u8; O] {
    sponge::<N, O, 136, 31>(x)
}

mod tests;
mod instance_tests;

/// Compile-time guard for the public sponge APIs. FIPS 202 (sections 6.1, 6.2
/// and B.2) defines SHA3-224/256/384/512 with domain suffix 0x06 and rates 144,
/// 136, 104 and 72 bytes, and SHAKE128/256 with suffix 0x1F and rates 168 and
/// 136 bytes. Every allowed rate is a whole number of 64-bit lanes and below
/// 200, and both suffixes are nonzero and below 0x80, so pad10*1 stays
/// injective. Any other pair fails to compile.
fn assert_fips202_instance<let R: u32, let D: u32>() {
    let sha3 = (D == 6) & ((R == 144) | (R == 136) | (R == 104) | (R == 72));
    let shake = (D == 31) & ((R == 168) | (R == 136));
    std::static_assert(sha3 | shake, "not a FIPS 202 rate and domain suffix");
}

fn absorb<let N: u32, let R: u32, let D: u32, let CHECK: u32>(input: [u8; N]) -> [u64; 25] {
    assert_fips202_instance::<R, D>();
    let mut padded: [u8; (N / R + 1) * R] = [0; (N / R + 1) * R];
    for i in 0..N {
        padded[i] = input[i];
    }
    padded[N] = D as u8;
    padded[(N / R + 1) * R - 1] |= 128;
    let mut state = [0u64; 25];
    for b in 0..N / R + 1 {
        for lane in 0..R / 8 {
            // Eight bytes sum to at most 2^64-1, below the native modulus.
            // This linear packing replaces seven disjoint bitwise OR operations.
            let mut w = 0 as Field;
            for j in 0..8 {
                w += (padded[b * R + lane * 8 + j] as Field) * ((1u64 << (8 * j) as u64) as Field);
            }
            // FIPS 202 lane layout: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
            // Local refinement: sum(byte[j]*256^j) <= 2^64-1 < p.
            // This bound excludes no byte input and avoids general Field truncation.
            // CHECK=0 preserves the existing byte-sponge compiled relation.
            if CHECK == 1 {
                w.assert_max_bit_size::<64>();
            }
            state[lane] ^= w as u64;
        }
        state = std::hash::keccakf1600(state);
    }
    state
}
/// FIPS 202 sections 4/6: same absorb/pad/permutation as the byte sponge.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
/// Returns L little-endian 64-bit lanes of the squeeze stream. Standard callers
/// use R=72,136,168. R and D must name a FIPS 202 instance (see
/// assert_fips202_instance).
/// A rate boundary advances the permutation exactly once. Full lanes expose
/// no new entropy; they are precisely the existing byte stream in groups of 8.
pub fn sponge_lanes<let N: u32, let L: u32, let R: u32, let D: u32>(input: [u8; N]) -> [u64; L] {
    squeeze_lanes::<L, R>(absorb::<N, R, D, 1>(input))
}
fn squeeze_lanes<let L: u32, let R: u32>(mut state: [u64; 25]) -> [u64; L] {
    let mut out = [0u64; L];
    for b in 0..(L + R / 8 - 1) / (R / 8) {
        for lane in 0..R / 8 {
            if b * (R / 8) + lane < L {
                out[b * (R / 8) + lane] = state[lane];
            }
        }
        if (b + 1) * (R / 8) < L {
            state = std::hash::keccakf1600(state);
        }
    }
    out
}

/// Exact FIPS 202 sponge for inputs consisting of complete little-endian lanes.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
/// N input words mean exactly 8*N input bytes; no partial-word padding is hidden.
/// The suffix starts in the next word and the final padding bit is bit 63 of
/// the final rate word. An exact rate multiple therefore adds a new full block.
pub fn sponge_words<let N: u32, let L: u32, let R: u32, let D: u32>(input: [u64; N]) -> [u64; L] {
    assert_fips202_instance::<R, D>();
    let mut padded = [0u64; (N / (R / 8) + 1) * (R / 8)];
    for i in 0..N {
        (input[i] as Field).assert_max_bit_size::<64>();
        padded[i] = input[i];
    }
    padded[N] = D as u64;
    padded[(N / (R / 8) + 1) * (R / 8) - 1] |= 9223372036854775808;
    let mut state = [0u64; 25];
    for b in 0..N / (R / 8) + 1 {
        for i in 0..R / 8 {
            state[i] ^= padded[b * (R / 8) + i];
        }
        state = std::hash::keccakf1600(state);
    }
    squeeze_lanes::<L, R>(state)
}
