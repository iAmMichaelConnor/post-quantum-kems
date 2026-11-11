//! FIPS 203 Algorithms 7/8 (SampleNTT/SamplePolyCBD), with local circuit reductions.
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
//! The optimisations below preserve the reference bit stream and sampling law.
use crate::{poly::Poly, sponge};
pub fn sample_ntt(rho: [u8; 32], x: u8, y: u8) -> Poly {
    // Appendix B permits 280 triplets (840 bytes). All 105 lanes of all five
    // SHAKE128 blocks are expanded: no shorter sampling prefix is assumed.
    // 3 little-endian 64-bit lanes = 16 little-endian 12-bit candidates.
    let lanes = fips202::sponge_lanes::<34, 105, 168, 31>(sponge::join(rho, [x, y]));
    let mut candidates = [0u16; 560];
    for group in 0..35 {
        let values = decode_lanes(
            [lanes[3 * group], lanes[3 * group + 1], lanes[3 * group + 2]],
        );
        for j in 0..16 {
            candidates[16 * group + j] = values[j];
        }
    }
    parse_candidates(candidates)
}
fn decode_lanes(lanes: [u64; 3]) -> [u16; 16] {
    decode_words::<12, 16, 3>(lanes)
}
fn check_lanes(lanes: [u64; 3], values: [u16; 16]) {
    check_words::<12, 16, 3>(lanes, values);
}
fn decode_words<let D: u32, let N: u32, let L: u32>(lanes: [u64; L]) -> [u16; N] {
    // Safety: all digits and both full integer reconstructions are checked.
    // L <= 3 and 64*L = D*N imply both sides < 2^192, below the native modulus.
    let values = unsafe { decode_words_hint::<D, N, L>(lanes) };
    check_words::<D, N, L>(lanes, values);
    values
}
fn check_words<let D: u32, let N: u32, let L: u32>(lanes: [u64; L], values: [u16; N]) {
    assert((L > 0) & (L <= 3) & (D > 0) & (D <= 16) & (64 * L == D * N));
    let mut packed = 0 as Field;
    let mut base = 1 as Field;
    for j in 0..L {
        packed += lanes[j] as Field * base;
        base *= 18446744073709551616;
    }
    let mut repacked = 0 as Field;
    base = 1;
    for j in 0..N {
        // When a caller uses this digit as a table index (cbd_lookup), the compiler
        // drops this check and the backend's memory bound enforces it instead; see
        // docs/CORRECTNESS.md#backend-and-compiler-premises.
        (values[j] as Field).assert_max_bit_size::<D>();
        repacked += (values[j] as Field) * base;
        base *= (1u32 << D) as Field;
    }
    assert(packed == repacked, "lane digits do not repack");
}
unconstrained fn decode_words_hint<let D: u32, let N: u32, let L: u32>(
    lanes: [u64; L],
) -> [u16; N] {
    let mut values = [0u16; N];
    for j in 0..N {
        let bit = D * j;
        let index = bit / 64;
        let shift = bit % 64;
        let mut value = lanes[index] >> (shift as u64);
        // A crossing can only occur before the final lane because D*N=64*L.
        if shift + D > 64 {
            value |= lanes[index + 1] << ((64 - shift) as u64);
        }
        values[j] = (value & ((1u64 << (D as u64)) - 1)) as u16;
    }
    values
}
pub fn parse_ntt(bytes: [u8; 840]) -> Poly {
    let mut candidates = [0u16; 560];
    for i in 0..280 {
        candidates[2 * i] = bytes[3 * i] as u16 + 256 * (bytes[3 * i + 1] as u16 % 16);
        candidates[2 * i + 1] = bytes[3 * i + 1] as u16 / 16 + 16 * bytes[3 * i + 2] as u16;
    }
    parse_candidates(candidates)
}
fn parse_candidates(candidates: [u16; 560]) -> Poly {
    // Safety: check_candidates validates every hinted index and output against
    // the complete constrained candidate stream; the hint cannot select noise.
    let (out, indices) = unsafe { parse_candidates_hint(candidates) };
    check_candidates(candidates, out, indices)
}
fn check_candidates(candidates: [u16; 560], out: [u16; 256], indices: [u16; 256]) -> Poly {
    // Local exact radix argument: tag rejected candidates in the high digit.
    // record = candidate + 4096*(prefix + 1024*rejected), with candidate<4096,
    // prefix<=560, and the checked rejected bit. Thus record<6492160<2^23.
    // A 12-bit output j matching record=out+4096*(j+1) has candidate=out
    // and prefix+1024*rejected=j+1<=256. Hence rejected=0 and candidate<q;
    // this derives output canonicality without a second output range check.
    // For each prefix j+1 there is exactly one accepted candidate. All 560
    // candidates are checked, so late index 559 succeeds and exhaustion fails.
    // Safety: each flag is checked Boolean and tied to its candidate by the
    // exact range relation below; batching changes only hint generation cost.
    let rejected = unsafe { rejected_flags_hint(candidates) };
    let mut records = [0 as Field; 560];
    let mut count = 0 as Field;
    for i in 0..560 {
        (candidates[i] as Field).assert_max_bit_size::<12>();
        count += check_acceptance(candidates[i], rejected[i]);
        records[i] = candidates[i] as Field + 4096 * (count + 1024 * rejected[i]);
    }
    let mut result = [0u32; 256];
    for j in 0..256 {
        // The only constraint on an index is the memory bound index < 560 of this
        // read, enforced by the backend; see docs/CORRECTNESS.md#backend-and-compiler-premises.
        check_record(records[indices[j] as u32], out[j] as Field, j);
        result[j] = out[j] as u32;
    }
    result
}
fn check_record(record: Field, out: Field, index: u32) {
    // Caller uses index 0..255. This bound on out is essential: otherwise an
    // out+4096 carry could move a later accepted candidate into an earlier slot.
    out.assert_max_bit_size::<12>();
    assert(record == out + 4096 * ((index + 1) as Field), "candidate record mismatch");
}
fn check_acceptance(value: u16, rejected: Field) -> Field {
    // For c in [0,4095], c+767 is in [767,4862]. Its bit 12 is exactly [c>=3329].
    // Boolean b and the 12-bit range on c+767-4096*b uniquely determine b.
    // Wrong b gives a negative integer or >=4096, so cannot pass the range.
    (value as Field).assert_max_bit_size::<12>();
    assert(rejected * (rejected - 1) == 0, "rejection flag is not boolean");
    (value as Field + 767 - 4096 * rejected).assert_max_bit_size::<12>();
    1 - rejected
}
unconstrained fn rejected_flags_hint(candidates: [u16; 560]) -> [Field; 560] {
    let mut flags = [0 as Field; 560];
    for i in 0..560 {
        flags[i] = (candidates[i] >= 3329) as Field;
    }
    flags
}
unconstrained fn parse_candidates_hint(candidates: [u16; 560]) -> ([u16; 256], [u16; 256]) {
    let mut out = [0u16; 256];
    let mut indices = [0u16; 256];
    let mut count = 0u16;
    for i in 0..560 {
        if (candidates[i] < 3329) & (count != 256) {
            out[count as u32] = candidates[i];
            indices[count as u32] = i as u16;
            count += 1;
        }
    }
    assert(count == 256, "SampleNTT exhausted");
    (out, indices)
}
pub fn cbd<let ETA: u32>(bytes: [u8; 64 * ETA]) -> Poly {
    // FIPS 203 SamplePolyCBD: each coefficient consumes 2*ETA consecutive bits.
    // Supported KEMs use ETA 2/3. Grouped decoding checks every 4/6-bit input word;
    // the constant table exhausts all possibilities and returns
    // popcount(low ETA bits)-popcount(high ETA bits) modulo 3329. This local
    // ROM implementation changes neither bit order nor noise distribution.
    assert((ETA == 2) | (ETA == 3));
    let decoded = crate::poly::decode::<2 * ETA>(bytes, false);
    let mut words = [0u16; 256];
    for i in 0..256 {
        words[i] = decoded[i] as u16;
    }
    cbd_words::<ETA>(words)
}
fn cbd_words<let ETA: u32>(words: [u16; 256]) -> Poly {
    if ETA == 2 {
        cbd_lookup::<2, 16>(words)
    } else {
        assert(ETA == 3);
        cbd_lookup::<3, 64>(words)
    }
}
fn cbd_lookup<let ETA: u32, let T: u32>(words: [u16; 256]) -> Poly {
    assert(T == 1 << (2 * ETA));
    let mut table = [0u16; T];
    for value in 0..T {
        let mut a = 0u16;
        let mut b = 0u16;
        for bit in 0..ETA {
            a += ((value >> bit) & 1) as u16;
            b += ((value >> (bit + ETA)) & 1) as u16;
        }
        table[value] = (a + 3329 - b) % 3329;
    }
    let mut out = [0u32; 256];
    for i in 0..256 {
        // Compiled, this bound is the memory bound word < T = 2^(2*ETA) of the read
        // below, enforced by the backend; see docs/CORRECTNESS.md#backend-and-compiler-premises.
        (words[i] as Field).assert_max_bit_size::<2 * ETA>();
        out[i] = table[words[i] as u32] as u32;
    }
    out
}
pub fn noise<let ETA: u32>(seed: [u8; 32], nonce: u8) -> Poly {
    assert((ETA == 2) | (ETA == 3));
    // SamplePolyCBD consumes 64*ETA bytes = 8*ETA lanes. For ETA 2 one 64-bit
    // lane contains 16 four-bit words; for ETA 3 three lanes contain 32 six-bit
    // words. The grouping follows the concatenated stream across rate blocks.
    let lanes = fips202::sponge_lanes::<33, 8 * ETA, 136, 31>(sponge::join(seed, [nonce]));
    let mut words = [0u16; 256];
    if ETA == 2 {
        for group in 0..16 {
            let values = decode_words::<4, 16, 1>([lanes[group]]);
            for j in 0..16 {
                words[16 * group + j] = values[j];
            }
        }
    } else {
        for group in 0..8 {
            let values = decode_words::<6, 32, 3>([
                lanes[3 * group],
                lanes[3 * group + 1],
                lanes[3 * group + 2],
            ]);
            for j in 0..32 {
                words[32 * group + j] = values[j];
            }
        }
    }
    cbd_words::<ETA>(words)
}
pub fn noise1<let K: u32>(seed: [u8; 32], nonce: u8) -> Poly {
    if K == 2 {
        noise::<3>(seed, nonce)
    } else {
        noise::<2>(seed, nonce)
    }
}

mod tests;
