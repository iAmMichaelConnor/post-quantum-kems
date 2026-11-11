use super::{
    cbd, check_candidates, check_lanes, decode_lanes, parse_candidates, parse_candidates_hint,
};

fn lane_boundaries() {
    assert(decode_lanes(std::hint::black_box([0u64; 3])) == [0u16; 16]);
    assert(decode_lanes(std::hint::black_box([18446744073709551615u64; 3])) == [4095u16; 16]);
    let positions = [0, 59, 60, 63, 64, 65, 119, 120, 127, 128, 131, 191];
    for i in 0..12 {
        let bit = positions[i];
        let mut lanes = [0u64; 3];
        lanes[bit / 64] = 1u64 << ((bit % 64) as u64);
        let mut expected = [0u16; 16];
        expected[bit / 12] = 1u16 << ((bit % 12) as u16);
        assert(decode_lanes(std::hint::black_box(lanes)) == expected);
    }
}
#[test]
fn constrained_lane_boundaries() {
    lane_boundaries();
}
#[test]
unconstrained fn brillig_lane_boundaries() {
    lane_boundaries();
}
#[test(should_fail_with = "lane digits do not repack")]
fn rejects_forged_lane_digit() {
    let mut wrong = [0u16; 16];
    wrong[5] = 1;
    check_lanes(std::hint::black_box([0u64; 3]), wrong);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_overflow_lane_digit() {
    // Integer packing alone would accept this carry into the next radix digit.
    let mut wrong = [0u16; 16];
    wrong[0] = 4096;
    check_lanes(std::hint::black_box([4096u64, 0, 0]), wrong);
}
fn candidate_boundaries() {
    assert(parse_candidates(std::hint::black_box([0u16; 560])) == [0u32; 256]);
    let mut candidates = [4095u16; 560];
    let mut expected = [0u32; 256];
    for i in 0..256 {
        candidates[304 + i] = i as u16;
        expected[i] = i;
    }
    assert(parse_candidates(std::hint::black_box(candidates)) == expected);
    for i in 0..560 {
        candidates[i] = i as u16;
    }
    assert(parse_candidates(std::hint::black_box(candidates)) == expected);
}
#[test]
fn constrained_candidate_boundaries() {
    candidate_boundaries();
}
#[test]
unconstrained fn brillig_candidate_boundaries() {
    candidate_boundaries();
}
fn candidate_fixture() -> ([u16; 560], [u16; 256], [u16; 256]) {
    let mut candidates = [0u16; 560];
    for i in 0..560 {
        candidates[i] = i as u16;
    }
    let candidates = std::hint::black_box(candidates);
    // Safety: the fixture outputs are passed to the full constrained checker
    // in every caller; each deliberate corruption must be rejected there.
    let (out, indices) = unsafe { parse_candidates_hint(candidates) };
    (candidates, out, indices)
}
#[test(should_fail_with = "candidate record mismatch")]
fn rejects_shifted_candidate_index() {
    let (candidates, out, mut indices) = candidate_fixture();
    indices[255] = 256;
    let _ = check_candidates(candidates, out, indices);
}
#[test(should_fail_with = "candidate record mismatch")]
fn rejects_duplicated_candidate_index() {
    let (candidates, mut out, mut indices) = candidate_fixture();
    indices[255] = 0;
    out[255] = 0;
    let _ = check_candidates(candidates, out, indices);
}
// ACVM evidence only: execution stops in the memory solver ("Index out of bounds").
// The index is black-boxed so that the read is not folded at compile time. In the
// circuit the bound is the backend's memory bound index < 560; see
// docs/CORRECTNESS.md#backend-and-compiler-premises.
#[test(should_fail_with = "Index out of bounds")]
fn rejects_out_of_bounds_candidate_index() {
    let (candidates, out, mut indices) = candidate_fixture();
    indices[255] = std::hint::black_box(560);
    let _ = check_candidates(candidates, out, indices);
}
#[test(should_fail_with = "candidate record mismatch")]
fn rejects_forged_candidate_output() {
    let (candidates, mut out, indices) = candidate_fixture();
    out[255] = 256;
    let _ = check_candidates(candidates, out, indices);
}
#[test(should_fail_with = "candidate record mismatch")]
fn rejects_candidate_output_modulus_alias() {
    let (candidates, mut out, indices) = candidate_fixture();
    out[255] = 3329;
    let _ = check_candidates(candidates, out, indices);
}
#[test(should_fail_with = "candidate record mismatch")]
fn rejects_exhausted_candidate_checker() {
    let _ = check_candidates(std::hint::black_box([4095u16; 560]), [0; 256], [0; 256]);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_candidate_radix_carry_forgery() {
    // Without the 12-bit check,4096 would masquerade as the nonexistent 256th
    // accepted zero: 4096+4096*255 = 0+4096*256. There are only 255 accepts.
    let mut candidates = [4095u16; 560];
    let mut indices = [0u16; 256];
    for i in 0..255 {
        candidates[i] = 0;
        indices[i] = i as u16;
    }
    candidates[255] = 4096;
    indices[255] = 255;
    let _ = check_candidates(std::hint::black_box(candidates), [0; 256], indices);
}
fn cbd_reference<let ETA: u32>(bytes: [u8; 64 * ETA]) -> [u32; 256] {
    let mut out = [0u32; 256];
    for i in 0..256 {
        let mut a = 0u32;
        let mut b = 0u32;
        for j in 0..ETA {
            let ai = 2 * ETA * i + j;
            let bi = ai + ETA;
            a += ((bytes[ai / 8] >> ((ai % 8) as u8)) & 1) as u32;
            b += ((bytes[bi / 8] >> ((bi % 8) as u8)) & 1) as u32;
        }
        out[i] = (a + 3329 - b) % 3329;
    }
    out
}
fn cbd_exhaustive() {
    // Both 4/6-bit input domains are enumerated, including cross-byte words.
    let mut bytes2 = [0u8; 128];
    for i in 0..128 {
        bytes2[i] = (i % 16 + 16 * ((i / 16) % 16)) as u8;
    }
    let bytes2 = std::hint::black_box(bytes2);
    assert(cbd::<2>(bytes2) == cbd_reference::<2>(bytes2));
    let mut bytes3 = [0u8; 192];
    for group in 0..64 {
        let packed = group
            + ((group + 1) % 64) * 64
            + ((group + 2) % 64) * 4096
            + ((group + 3) % 64) * 262144;
        bytes3[3 * group] = (packed & 255) as u8;
        bytes3[3 * group + 1] = ((packed >> 8) & 255) as u8;
        bytes3[3 * group + 2] = ((packed >> 16) & 255) as u8;
    }
    let bytes3 = std::hint::black_box(bytes3);
    assert(cbd::<3>(bytes3) == cbd_reference::<3>(bytes3));
    assert(cbd::<2>(std::hint::black_box([0; 128])) == [0; 256]);
    assert(cbd::<2>(std::hint::black_box([255; 128])) == [0; 256]);
    assert(cbd::<3>(std::hint::black_box([0; 192])) == [0; 256]);
    assert(cbd::<3>(std::hint::black_box([255; 192])) == [0; 256]);
}
#[test]
fn constrained_cbd_exhaustive() {
    cbd_exhaustive();
}
#[test]
unconstrained fn brillig_cbd_exhaustive() {
    cbd_exhaustive();
}

fn acceptance_boundaries() {
    assert(super::check_acceptance(std::hint::black_box(0u16), 0) == 1);
    assert(super::check_acceptance(std::hint::black_box(3328u16), 0) == 1);
    assert(super::check_acceptance(std::hint::black_box(3329u16), 1) == 0);
    assert(super::check_acceptance(std::hint::black_box(4095u16), 1) == 0);
}
#[test]
fn constrained_acceptance_boundaries() {
    acceptance_boundaries();
}
#[test]
unconstrained fn brillig_acceptance_boundaries() {
    acceptance_boundaries();
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_acceptance_bit_false_rejection() {
    let _ = super::check_acceptance(std::hint::black_box(3328u16), 1);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_acceptance_bit_false_acceptance() {
    let _ = super::check_acceptance(std::hint::black_box(3329u16), 0);
}
#[test(should_fail_with = "rejection flag is not boolean")]
fn rejects_acceptance_non_boolean_flag() {
    let _ = super::check_acceptance(std::hint::black_box(3329u16), 2);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_candidate_output_max_u16() {
    let (candidates, mut out, indices) = candidate_fixture();
    out[255] = 65535;
    let _ = check_candidates(candidates, out, indices);
}
// check_words alone, with black-boxed words: no table read follows, so the RANGE 6
// opcode stays and ACVM rejects the word. In noise() the bound is the cbd_lookup
// memory read instead.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_noise_word_overflow() {
    let mut words = [0u16; 32];
    words[0] = 64;
    super::check_words::<6, 32, 3>(
        std::hint::black_box([64u64, 0, 0]),
        std::hint::black_box(words),
    );
}
fn noise_lanes_match_bytes() {
    let seeds = [[0u8; 32], [255u8; 32]];
    let nonces = [0u8, 255u8];
    for i in 0..2 {
        let seed = std::hint::black_box(seeds[i]);
        let nonce = nonces[i];
        let bytes2 = crate::sponge::shake256::<33, 128>(crate::sponge::join(seed, [nonce]));
        let bytes3 = crate::sponge::shake256::<33, 192>(crate::sponge::join(seed, [nonce]));
        assert(super::noise::<2>(seed, nonce) == cbd::<2>(bytes2));
        assert(super::noise::<3>(seed, nonce) == cbd::<3>(bytes3));
    }
    assert(
        super::decode_words::<4, 16, 1>(std::hint::black_box([18446744073709551615u64]))
            == [15u16; 16],
    );
    assert(
        super::decode_words::<6, 32, 3>(std::hint::black_box([18446744073709551615u64; 3]))
            == [63u16; 32],
    );
}
#[test]
fn constrained_noise_lanes_match_bytes() {
    noise_lanes_match_bytes();
}
#[test]
unconstrained fn brillig_noise_lanes_match_bytes() {
    noise_lanes_match_bytes();
}
#[test(should_fail_with = "rejection flag is not boolean")]
fn rejects_acceptance_fractional_flag() {
    let _ = super::check_acceptance(std::hint::black_box(3329u16), 1 / (2 as Field));
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_tagged_record_output_carry() {
    // A later accepted candidate with prefix 2 and value1 could masquerade as
    // first output 4097 if the explicit 12-bit output guard were removed.
    super::check_record(std::hint::black_box(8193), std::hint::black_box(4097), 0);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_tagged_rejected_record_output_alias() {
    // Rejected candidate 4095, prefix 0, tag 1024. A large hinted output could
    // absorb the tag if its 12-bit bound were omitted.
    super::check_record(
        std::hint::black_box(4198399),
        std::hint::black_box(4194303),
        0,
    );
}
#[test]
fn constrained_tagged_last_maximal_candidate() {
    let mut candidates = [4095u16; 560];
    for i in 304..560 {
        candidates[i] = 3328;
    }
    assert(parse_candidates(std::hint::black_box(candidates)) == [3328u32; 256]);
}
#[test]
unconstrained fn brillig_tagged_last_maximal_candidate() {
    let mut candidates = [4095u16; 560];
    for i in 304..560 {
        candidates[i] = 3328;
    }
    assert(parse_candidates(std::hint::black_box(candidates)) == [3328u32; 256]);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_tagged_rejection_after_first_acceptance() {
    // After accepting zero, c=3329 has prefix 1 and rejected tag 1024.
    // Removing out12 would let the rejected record encode output 3329+2^22.
    super::check_record(
        std::hint::black_box(4201729),
        std::hint::black_box(4197633),
        0,
    );
}
