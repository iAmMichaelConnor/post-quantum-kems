// All internal coefficients are canonical integers in [0,3329).
pub type Poly = [u32; 256];
pub global Q: u32 = 3329;
// Integer reduction for a nonnegative expression x with x/3329 < 2^B.
// Bounds at every caller are recorded in docs/OPTIMISATIONS.md.
// Both ranges are over native Field integers. r<4096 and r+767<4096
// are equivalent to 0<=r<3329; their sums cannot wrap the native modulus.
fn assert_canonical_remainder(r: Field) {
    r.assert_max_bit_size::<12>();
    (r + 767).assert_max_bit_size::<12>();
}
fn divrem<let B: u32>(x: Field) -> (u32, u32) {
    // Safety: range checks and the integer equation constrain both hint outputs.
    let (quotient, remainder) = unsafe { division_hint(x) };
    division_relation::<B>(x, quotient, remainder)
}
fn division_relation<let B: u32>(x: Field, quotient: Field, remainder: Field) -> (u32, u32) {
    quotient.assert_max_bit_size::<B>();
    assert_canonical_remainder(remainder);
    assert(x == quotient * 3329 + remainder, "wrong division quotient or remainder");
    (quotient as u32, remainder as u32)
}
unconstrained fn division_hint(x: Field) -> (Field, Field) {
    let n = x as u64;
    ((n / 3329) as Field, (n % 3329) as Field)
}
fn reduce<let B: u32>(x: Field) -> u32 {
    divrem::<B>(x).1
}
pub fn addq(a: u32, b: u32) -> u32 {
    reduce::<1>(a as Field + b as Field)
}
pub fn subq(a: u32, b: u32) -> u32 {
    reduce::<1>(a as Field + 3329 - b as Field)
}
pub fn mulq(a: u32, b: u32) -> u32 {
    reduce::<12>((a as Field) * (b as Field))
}
pub fn add(a: Poly, b: Poly) -> Poly {
    let mut c = [0; 256];
    for i in 0..256 {
        c[i] = addq(a[i], b[i]);
    }
    c
}
pub fn sub(a: Poly, b: Poly) -> Poly {
    let mut c = [0; 256];
    for i in 0..256 {
        c[i] = subq(a[i], b[i]);
    }
    c
}
// Locally derived fusion of FIPS 203 Algorithms 9/10, not a new NTT.
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
// Construct each block's constant linear map by applying the original butterfly
// schedule to the identity matrix, reducing constants modulo q at compile time.
fn transform_matrix<let FIRST: u32, let COUNT: u32, let N: u32>(
    block: u32,
    inverse: bool,
) -> [[u32; N]; N] {
    let size = N;
    assert((COUNT > 0) & (FIRST + COUNT <= 7));
    assert(N == 1 << COUNT);
    let mut matrix = [[0u32; N]; N];
    for i in 0..size {
        matrix[i][i] = 1;
    }
    for step in 0..COUNT {
        let stage = FIRST + step;
        let len = if inverse {
            1 << step
        } else {
            size >> (step + 1)
        };
        let subblocks = size / (2 * len);
        for subblock in 0..subblocks {
            let index = if inverse {
                (128 >> stage) - 1 - (block * subblocks + subblock)
            } else {
                (1 << stage) + block * subblocks + subblock
            };
            let z = ZETAS[index];
            for offset in 0..len {
                let j = subblock * 2 * len + offset;
                for column in 0..size {
                    let x = matrix[j][column];
                    let y = matrix[j + len][column];
                    if inverse {
                        matrix[j][column] = (x + y) % Q;
                        matrix[j + len][column] = (z * (y + Q - x)) % Q;
                    } else {
                        matrix[j][column] = (x + z * y) % Q;
                        matrix[j + len][column] = (x + Q * Q - z * y) % Q;
                    }
                }
            }
        }
    }
    if inverse & (FIRST + COUNT == 7) {
        for i in 0..size {
            for j in 0..size {
                matrix[i][j] = matrix[i][j] * 3303 % Q;
            }
        }
    }
    matrix
}
// Matrix coefficients are first reduced modulo q, then centered at zero.
// Canonical inputs <=3328 make each corrected term nonnegative. With N=2^COUNT,
// x<=N*1664*3328+3328+6656, so quotient<N*1664+3<2^(11+COUNT)
// for N>=2. Both sides remain far below the native-field modulus.
// Matrices are constants; no zero, invertibility, or exceptional-input test is
// introduced. Reducing only each block's final outputs preserves every input.
fn transform_stages<let FIRST: u32, let COUNT: u32, let N: u32>(
    a: Poly,
    inverse: bool,
    b: Poly,
    c: Poly,
) -> Poly {
    transform_stages_output::<FIRST, COUNT, N, 0>(a, inverse, b, c)
}
// D = 0 keeps canonical outputs; D = 4 or 10 fuses the final inverse group
// with compression. All modes share the exact same matrix and linear arithmetic.
fn transform_stages_output<let FIRST: u32, let COUNT: u32, let N: u32, let D: u32>(
    mut a: Poly,
    inverse: bool,
    b: Poly,
    c: Poly,
) -> Poly {
    let size = N;
    assert((COUNT > 0) & (FIRST + COUNT <= 7));
    assert(N == 1 << COUNT);
    if D != 0 {
        assert(inverse & (FIRST == 3) & (COUNT == 4) & ((D == 4) | (D == 10)));
    }
    let stride = if inverse {
        2 << FIRST
    } else {
        256 >> (FIRST + COUNT)
    };
    let blocks = 256 / (size * stride);
    for block in 0..blocks {
        let matrix = transform_matrix::<FIRST, COUNT, N>(block, inverse);
        for offset in 0..stride {
            let mut inputs = [0u32; N];
            for i in 0..size {
                inputs[i] = a[block * size * stride + i * stride + offset];
            }
            for row in 0..size {
                // Center each constant into[-1664,1664]. For -d, use
                // d*(3328-input), then add sum(d) modq because3328=-1 modq.
                // Canonical inputs make every product nonnegative. The sum is
                // <=N*1664*3328+3328+6656, quotient<2^(11+COUNT) forN>=2.
                let mut x: Field = 0;
                let mut correction = 0u32;
                let mut maximum = 0u64;
                for column in 0..size {
                    let coefficient = matrix[row][column];
                    if coefficient > 1664 {
                        let d = Q - coefficient;
                        correction += d;
                        maximum += d as u64 * 3328;
                        x += d as Field * (3328 - inputs[column] as Field);
                    } else {
                        maximum += coefficient as u64 * 3328;
                        x += coefficient as Field * inputs[column] as Field;
                    }
                }
                x += (correction % Q) as Field;
                maximum += (correction % Q) as u64;
                let index = block * size * stride + row * stride + offset;
                if inverse & (FIRST + COUNT == 7) {
                    x += b[index] as Field + c[index] as Field;
                    maximum += 6656;
                }
                // Locally derived bound for the FIPS 203 linear map above.
                // Every centered product is nonnegative and at most abs(c)*3328.
                // This maximum uses actual constant coefficients and includes both
                // canonical addends only after final inverse scaling. N <= 128,
                // so maximum < 2^30 and all u64 bound arithmetic is exact.
                // These conditions are compile-time constants, never input guards.
                a[index] = if D == 0 {
                    if (COUNT > 3) & (maximum / 3329 < (1u64 << 14)) {
                        reduce::<14>(x)
                    } else {
                        reduce::<11 + COUNT>(x)
                    }
                } else {
                    // Include the rounded quotient's possible endpoint wrap.
                    // D is 4 or 10 here; scaled maximum < 2^37 for this final group.
                    let high_maximum =
                        (((1u64 << D as u64) * maximum + 1664) / 3329) / (1u64 << D as u64);
                    if high_maximum < (1u64 << 14) {
                        compress_unreduced::<D, 14>(x)
                    } else {
                        compress_unreduced::<D, 15>(x)
                    }
                };
            }
        }
    }
    a
}
pub fn ntt(a: Poly) -> Poly {
    transform_stages::<3, 4, 16>(
        transform_stages::<0, 3, 8>(a, false, [0; 256], [0; 256]),
        false,
        [0; 256],
        [0; 256],
    )
}
pub fn inverse_ntt(a: Poly) -> Poly {
    inverse_ntt_add(a, [0; 256], [0; 256])
}
// Caller supplies canonical addends. Add both after the inverse linear map,
// before its final modular reduction. The centered sum is bounded by
// N*1664*3328+3328+6656, giving quotient<2^(11+COUNT) for N>=2. Noise and message
// polynomials may be zero or maximal; no exceptional input is excluded.
pub fn inverse_ntt_add(a: Poly, b: Poly, c: Poly) -> Poly {
    transform_stages::<3, 4, 16>(
        transform_stages::<0, 3, 8>(a, true, [0; 256], [0; 256]),
        true,
        b,
        c,
    )
}
// Locally derived composition of FIPS 203 Algorithm 10 and Eq. (4.7):
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
// For x = q*t + a, floor((2^D*x + 1664)/q) = 2^D*t + floor((2^D*a + 1664)/q).
// Thus its low D bits equal Compress_D(a), including the final rounding wrap.
// The final 16-term centered inverse sum including two canonical addends is
// <= 16*1664*3328 + 9984 = 88614656. The high quotient h <= floor(x/q) + 1 < 2^15.
// Scaled x and the verifier RHS are < 2^37 for D = 10, so both are exact integers in
// the native field and the u64 hint. No input canonicalization is skipped at
// an external boundary: only this unused intermediate canonical result is removed.
pub fn inverse_ntt_compress_add<let D: u32>(a: Poly, b: Poly, c: Poly) -> Poly {
    transform_stages_output::<3, 4, 16, D>(
        transform_stages::<0, 3, 8>(a, true, [0; 256], [0; 256]),
        true,
        b,
        c,
    )
}
pub fn multiply_ntt(a: Poly, b: Poly) -> Poly {
    multiply_accumulate_ntt([0; 256], a, b)
}
// Canonical accumulator and factors; combines the complete coefficient before reduction.
pub fn multiply_accumulate_ntt(mut c: Poly, a: Poly, b: Poly) -> Poly {
    for i in 0..128 {
        let gamma = if i % 2 == 0 {
            ZETAS[64 + i / 2]
        } else {
            Q - ZETAS[64 + i / 2]
        };
        c[2 * i] = reduce::<24>(
            (c[2 * i] as Field)
                + (a[2 * i] as Field) * (b[2 * i] as Field)
                + (gamma as Field) * (a[2 * i + 1] as Field) * (b[2 * i + 1] as Field),
        );
        c[2 * i + 1] = reduce::<13>(
            (c[2 * i + 1] as Field)
                + (a[2 * i] as Field) * (b[2 * i + 1] as Field)
                + (a[2 * i + 1] as Field) * (b[2 * i] as Field),
        );
    }
    c
}
// Sum the complete rank-K NTT dot product before each modular reduction.
// K<=3, canonical factors/accumulator. Even quotient <3*3328^2<2^25;
// odd quotient <6*3328^2/3329+1<2^15. Integer inputs are below 2^37.
pub fn dot_ntt<let K: u32>(a: [Poly; K], b: [Poly; K], acc: Poly) -> Poly {
    assert((K == 2) | (K == 3));
    let mut out = [0u32; 256];
    for i in 0..128 {
        let gamma = if i % 2 == 0 {
            ZETAS[64 + i / 2]
        } else {
            Q - ZETAS[64 + i / 2]
        };
        let mut even = acc[2 * i] as Field;
        let mut odd = acc[2 * i + 1] as Field;
        for j in 0..K {
            even += (a[j][2 * i] as Field) * (b[j][2 * i] as Field)
                + (gamma as Field) * (a[j][2 * i + 1] as Field) * (b[j][2 * i + 1] as Field);
            odd += (a[j][2 * i] as Field) * (b[j][2 * i + 1] as Field)
                + (a[j][2 * i + 1] as Field) * (b[j][2 * i] as Field);
        }
        out[2 * i] = reduce::<25>(even);
        out[2 * i + 1] = reduce::<15>(odd);
    }
    out
}
// FIPS 203 Algorithms 5/6 define ByteEncode/ByteDecode. This local circuit
// grouping uses injective packing: eight D-bit coefficients occupy D bytes.
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
// For D<=12, the largest integer is <2^96, so native-field packing cannot wrap.
fn pack_coefficients<let D: u32>(coefficients: [u32; 8]) -> Field {
    assert((D > 0) & (D <= 12));
    let mut packed = 0 as Field;
    for j in 0..8 {
        let coefficient = coefficients[j] as Field;
        // For D = 1 (encryption) and D = 4 (decryption) decode passes the coefficient
        // to decompress_lookup; the compiler then drops this check and the backend's
        // memory bound c < 2^D enforces it; see
        // docs/CORRECTNESS.md#backend-and-compiler-premises.
        coefficient.assert_max_bit_size::<D>();
        packed += coefficient * ((1u128 << ((D * j) as u128)) as Field);
    }
    packed
}
pub fn encode<let D: u32>(a: Poly) -> [u8; 32 * D] {
    let mut out = [0u8; 32 * D];
    for group in 0..32 {
        let mut coefficients = [0u32; 8];
        for j in 0..8 {
            coefficients[j] = a[group * 8 + j];
        }
        // At most 96 bits; no native-field wraparound is possible.
        let bytes = pack_coefficients::<D>(coefficients).to_le_bytes::<D>();
        for j in 0..D {
            out[group * D + j] = bytes[j];
        }
    }
    out
}
pub fn decode<let D: u32>(b: [u8; 32 * D], strict: bool) -> Poly {
    let mut out = [0; 256];
    for group in 0..32 {
        let mut packed = 0 as Field;
        for j in 0..D {
            packed += (b[group * D + j] as Field) * ((1u128 << ((8 * j) as u128)) as Field);
        }
        // Safety: all eight coefficient ranges and their exact packing are checked.
        let coefficients = unsafe { decode_coefficients_hint::<D>(packed) };
        assert(packed == pack_coefficients::<D>(coefficients));
        for j in 0..8 {
            let c = coefficients[j];
            out[group * 8 + j] = if D == 12 {
                if strict {
                    // pack_coefficients already proves c<4096; c+767<4096
                    // is exactly c<3329, with no native-field wrap.
                    (c as Field + 767).assert_max_bit_size::<12>();
                    c
                } else {
                    // ByteDecode12 intentionally reduces aliases for Kyber and
                    // ML-KEM decapsulation. c<=4095 gives quotient only0/1.
                    reduce::<1>(c as Field)
                }
            } else {
                c
            };
        }
    }
    out
}
unconstrained fn decode_coefficients_hint<let D: u32>(packed: Field) -> [u32; 8] {
    let packed = packed as u128;
    let mut out = [0u32; 8];
    for j in 0..8 {
        out[j] = ((packed >> ((D * j) as u128)) & ((1u128 << (D as u128)) - 1)) as u32;
    }
    out
}
// FIPS 203 Eq. (4.7): preserve the rounded quotient=2^D endpoint by masking.
// FIPS 203 Compress_d is round(2^d*x/q) mod 2^d. The quotient may
// equal 2^d, so a Boolean wrap is required even for a canonical x=q-1.
// This checked relation is locally derived to avoid a wide bitwise mask.
fn compression_relation<let D: u32>(
    x: Field,
    compressed: Field,
    wrap: Field,
    remainder: Field,
) -> u32 {
    compression_relation_bounded::<D, 1>(x, compressed, wrap, remainder)
}
// Current callers use D = 1, 4, or 10 and H = 1, 14, or 15. They establish that x is a
// nonnegative integer below 2^37; the checked RHS is also below 2^37.
// Thus the native-field equality is an integer equality, without field wrap.
fn compression_relation_bounded<let D: u32, let H: u32>(
    x: Field,
    compressed: Field,
    high: Field,
    remainder: Field,
) -> u32 {
    compressed.assert_max_bit_size::<D>();
    high.assert_max_bit_size::<H>();
    assert_canonical_remainder(remainder);
    assert(
        x == 3329 * (compressed + (1 << D) as Field * high) + remainder,
        "compression relation does not hold",
    );
    compressed as u32
}
unconstrained fn compression_hint<let D: u32>(x: Field) -> (Field, Field, Field) {
    let x = x as u64;
    let quotient = x / 3329;
    (
        (quotient % (1u64 << (D as u64))) as Field, (quotient / (1u64 << (D as u64))) as Field,
        (x % 3329) as Field,
    )
}
fn compress_unreduced<let D: u32, let H: u32>(value: Field) -> u32 {
    let scaled = (1 << D) as Field * value + 1664;
    // Safety: all three hint ranges and their full integer relation are checked.
    // Callers prove the scaled input and verifier RHS cannot wrap the native field.
    let (compressed, high, remainder) = unsafe { compression_hint::<D>(scaled) };
    compression_relation_bounded::<D, H>(scaled, compressed, high, remainder)
}
pub fn compress<let D: u32>(mut a: Poly) -> Poly {
    for i in 0..256 {
        a[i] = compress_unreduced::<D, 1>(a[i] as Field);
    }
    a
}
// FIPS 203 Eq. (4.8): nearest-integer scaling with the specified tie direction.
// Small-width exact ROM for FIPS 203 Eq. (4.8). Callers supply D-bit values
// from checked ByteDecode. Every table entry is computed at compile time;
// a constrained read fixes the result including both endpoint encodings.
// The table length must stay exactly 2^D: the read's memory bound a[i] < N is the
// compiled range check of the decoded coefficient (docs/CORRECTNESS.md#backend-and-compiler-premises).
fn decompress_lookup<let D: u32, let N: u32>(mut a: Poly) -> Poly {
    assert(N == 1 << D);
    let mut table = [0u32; N];
    for i in 0..N {
        table[i] = (Q * i + (1 << (D - 1))) >> D;
    }
    for i in 0..256 {
        a[i] = table[a[i]];
    }
    a
}
// Local exact-relation implementation of FIPS 203 Eq.(4.8), retaining upward
// half rounding: floor((q*c+2^(D-1))/2^D). For D10, inputc<=1023 gives
// x<=3406079 and output<=3326, canonical without a separate modulus comparison.
// Output12bits and remainder10bits bound the entire RHS by4194303<native p.
// Thus the relation is integer equality and determines a unique quotient.
fn decompression_relation<let D: u32>(c: Field, out: Field, remainder: Field) -> u32 {
    assert((D > 0) & (D <= 12));
    c.assert_max_bit_size::<D>();
    out.assert_max_bit_size::<12>();
    remainder.assert_max_bit_size::<D>();
    assert(
        3329 * c + (1 << (D - 1)) as Field == (1 << D) as Field * out + remainder,
        "decompression relation does not hold",
    );
    out as u32
}
unconstrained fn decompression_hint<let D: u32>(c: u32) -> (Field, Field) {
    let x = 3329 * (c as u64) + (1u64 << ((D - 1) as u64));
    ((x >> (D as u64)) as Field, (x & ((1u64 << (D as u64)) - 1)) as Field)
}
fn decompress_checked<let D: u32>(mut a: Poly) -> Poly {
    for i in 0..256 {
        // Safety: the encoded input, both hint ranges and the complete exact
        // integer division relation are checked immediately below.
        let (out, remainder) = unsafe { decompression_hint::<D>(a[i]) };
        a[i] = decompression_relation::<D>(a[i] as Field, out, remainder);
    }
    a
}
pub fn decompress<let D: u32>(mut a: Poly) -> Poly {
    if D == 1 {
        decompress_lookup::<1, 2>(a)
    } else if D == 4 {
        decompress_lookup::<4, 16>(a)
    } else if D == 10 {
        decompress_checked::<10>(a)
    } else {
        for i in 0..256 {
            a[i] = (Q * a[i] + (1 << (D - 1))) >> D;
        }
        a
    }
}

pub global ZETAS: [u32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807,
    452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649,
    1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789,
    1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375,
    2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143,
    2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

fn reduction_extremes() {
    let inputs: [u64; 7] = [0, 3328, 3329, 6657, 11075584, 22154496, 36870465536];
    for i in 0..7 {
        let x = std::hint::black_box(inputs[i]);
        let (q, r) = divrem::<24>(x as Field);
        assert(q as u64 == x / 3329);
        assert(r as u64 == x % 3329);
    }
    let a = std::hint::black_box([3328u32; 256]);
    assert(inverse_ntt(ntt(a)) == a);
    let c = multiply_ntt(a, a);
    let accumulated = multiply_accumulate_ntt(a, a, a);
    assert(accumulated == add(a, c));
    assert(dot_ntt::<2>([a; 2], [a; 2], a) == add(accumulated, c));
    assert(dot_ntt::<3>([a; 3], [a; 3], a) == add(add(accumulated, c), c));
    for i in 0..128 {
        let gamma = if i % 2 == 0 {
            ZETAS[64 + i / 2]
        } else {
            3329 - ZETAS[64 + i / 2]
        };
        assert(c[2 * i] == (1 + gamma) % 3329);
        assert(c[2 * i + 1] == 2);
    }
}
#[test]
fn constrained_reduction_extremes() {
    reduction_extremes();
}
#[test]
unconstrained fn brillig_reduction_extremes() {
    reduction_extremes();
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_short_quotient_bound() {
    let _ = divrem::<1>(std::hint::black_box(6658));
}

#[test(should_fail_with = "forged codec group")]
fn rejects_forged_codec_group() {
    let packed = std::hint::black_box(0 as Field);
    let mut wrong = [0u32; 8];
    wrong[7] = 1;
    assert(packed == pack_coefficients::<12>(wrong), "forged codec group");
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_codec_coefficient_overflow() {
    let _ = pack_coefficients::<10>([std::hint::black_box(1024u32); 8]);
}
#[test]
fn maximal_codec_groups() {
    // The maximal valid strict coefficient must remain accepted, paired with
    // the separate modulus-alias rejection test at3329.
    let canonical = std::hint::black_box([3328u32; 256]);
    assert(decode::<12>(encode::<12>(canonical), true) == canonical);
    let a = std::hint::black_box([4095u32; 256]);
    assert(encode::<12>(a) == [255u8; 384]);
    assert(decode::<12>([255u8; 384], false) == [766u32; 256]);
    assert(decode::<10>(encode::<10>([1023; 256]), false) == [1023; 256]);
    assert(decode::<4>(encode::<4>([15; 256]), false) == [15; 256]);
    assert(decode::<1>(encode::<1>([1; 256]), false) == [1; 256]);
}

// Test-only original FIPS butterfly schedule, retained for differential tests.
fn reference_ntt(mut a: Poly) -> Poly {
    for stage in 0..7 {
        let len = 128 >> stage;
        for block in 0..(1 << stage) {
            let zeta = ZETAS[(1 << stage) + block];
            for offset in 0..len {
                let j = block * 2 * len + offset;
                let t = (zeta as Field) * (a[j + len] as Field);
                let x = a[j] as Field;
                a[j] = reduce::<12>(x + t);
                a[j + len] = reduce::<12>(x + 3329 * 3329 - t);
            }
        }
    }
    a
}
fn reference_inverse_ntt(mut a: Poly) -> Poly {
    for stage in 0..7 {
        let len = 2 << stage;
        let blocks = 64 >> stage;
        for block in 0..blocks {
            let zeta = ZETAS[2 * blocks - 1 - block];
            for offset in 0..len {
                let j = block * 2 * len + offset;
                let x = a[j];
                let y = a[j + len];
                a[j] = addq(x, y);
                a[j + len] = reduce::<13>((zeta as Field) * (y as Field + 3329 - x as Field));
            }
        }
    }
    for i in 0..256 {
        a[i] = mulq(a[i], 3303);
    }
    a
}

fn fusion_boundaries() {
    for kind in 0..4 {
        let mut a = [0u32; 256];
        for i in 0..256 {
            a[i] = if kind == 0 {
                0
            } else if kind == 1 {
                3328
            } else if kind == 2 {
                if i % 2 == 0 {
                    0
                } else {
                    3328
                }
            } else {
                (i * i * 13 + 997 * i) % 3329
            };
        }
        let a = std::hint::black_box(a);
        assert(ntt(a) == reference_ntt(a));
        assert(inverse_ntt(a) == reference_inverse_ntt(a));
        assert(
            inverse_ntt_add(a, [3328; 256], [3328; 256])
                == add(add(reference_inverse_ntt(a), [3328; 256]), [3328; 256]),
        );
    }
}
#[test]
fn constrained_fusion_boundaries() {
    fusion_boundaries();
}
#[test]
unconstrained fn hint_fusion_boundaries() {
    fusion_boundaries();
}

fn compression_boundary_cases<let D: u32>() {
    // Include each supported width's first nonzero and final wrapping boundary:
    // D1:832/833,2496/2497; D4:104/105,3224/3225; D10:1/2,3327/3328.
    let inputs: [u32; 15] =
        [0, 1, 2, 104, 105, 832, 833, 1664, 1665, 2496, 2497, 3224, 3225, 3327, 3328];
    for i in 0..15 {
        let a = std::hint::black_box(inputs[i]);
        let x = (1 << D) as Field * a as Field + 1664;
        // Safety: compression_relation checks every hint range and the exact
        // integer equality before comparison with the independent rounding formula.
        let (c, w, r) = unsafe { compression_hint::<D>(x) };
        assert(compression_relation::<D>(x, c, w, r) == (((1 << D) * a + 1664) / 3329) % (1 << D));
    }
}
#[test]
fn constrained_compression_boundaries() {
    compression_boundary_cases::<1>();
    compression_boundary_cases::<4>();
    compression_boundary_cases::<10>();
    assert_canonical_remainder(std::hint::black_box(0));
    assert_canonical_remainder(std::hint::black_box(3328));
}
unconstrained fn exhaustive_compression_hint<let D: u32>() {
    for a in 0..3329 {
        let x = (1 << D) as Field * a as Field + 1664;
        let (c, w, r) = compression_hint::<D>(x);
        let expected = (((1 << D) * a + 1664) / 3329) % (1 << D);
        assert(c == expected as Field);
        assert(compression_relation::<D>(x, c, w, r) == expected);
    }
}
#[test]
unconstrained fn exhaustive_compression_hints() {
    exhaustive_compression_hint::<1>();
    exhaustive_compression_hint::<4>();
    exhaustive_compression_hint::<10>();
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_remainder_q() {
    assert_canonical_remainder(std::hint::black_box(3329));
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_remainder_4095() {
    assert_canonical_remainder(std::hint::black_box(4095));
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_remainder_native_alias() {
    assert_canonical_remainder(std::hint::black_box(-1));
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_compression_nonboolean_wrap() {
    let _ = compression_relation::<4>(
        std::hint::black_box(32 * 3329),
        std::hint::black_box(0),
        std::hint::black_box(2),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "compression relation does not hold")]
fn rejects_compression_wrong_wrap() {
    let _ = compression_relation::<4>(
        std::hint::black_box(16 * 3328 + 1664),
        std::hint::black_box(0),
        std::hint::black_box(0),
        std::hint::black_box(1648),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_compression_noncanonical_remainder() {
    let _ = compression_relation::<4>(
        std::hint::black_box(3329),
        std::hint::black_box(0),
        std::hint::black_box(0),
        std::hint::black_box(3329),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_compression_overflow() {
    let _ = compression_relation::<4>(
        std::hint::black_box(16 * 3329),
        std::hint::black_box(16),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "compression relation does not hold")]
fn rejects_compression_wrong_equation() {
    let _ = compression_relation::<4>(
        std::hint::black_box(1),
        std::hint::black_box(0),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_division_field_alias() {
    // Deliberate counterexample if the original r12-bit check were removed:
    // 2562 = 3329*1 +(-767) in Field, and r+767=0 passes the shifted check.
    let _ = division_relation::<1>(
        std::hint::black_box(2562),
        std::hint::black_box(1),
        std::hint::black_box(-767),
    );
}
#[test(should_fail_with = "wrong division quotient or remainder")]
fn rejects_division_wrong_quotient() {
    let _ = division_relation::<1>(
        std::hint::black_box(0),
        std::hint::black_box(1),
        std::hint::black_box(0),
    );
}
#[test]
fn constrained_small_decompression_tables() {
    let mut one = [0u32; 256];
    let mut four = [0u32; 256];
    for i in 0..256 {
        one[i] = i % 2;
        four[i] = i % 16;
    }
    let one = std::hint::black_box(one);
    let four = std::hint::black_box(four);
    let d1 = decompress::<1>(one);
    let d4 = decompress::<4>(four);
    for i in 0..256 {
        assert(d1[i] == (3329 * one[i] + 1) / 2);
        assert(d4[i] == (3329 * four[i] + 8) / 16);
    }
}

#[test]
fn constrained_checked_decompression_boundaries() {
    let values: [u32; 6] = [0, 1, 511, 512, 1022, 1023];
    for i in 0..6 {
        let c = std::hint::black_box(values[i]);
        // Safety: all hinted outputs are checked by the exact bounded relation.
        let (out, r) = unsafe { decompression_hint::<10>(c) };
        assert(decompression_relation::<10>(c as Field, out, r) == (3329 * c + 512) / 1024);
    }
}
#[test]
unconstrained fn exhaustive_checked_decompression_hints() {
    for c in 0..1024 {
        let (out, r) = decompression_hint::<10>(c);
        assert(decompression_relation::<10>(c as Field, out, r) == (3329 * c + 512) / 1024);
    }
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_decompression_remainder_overflow() {
    // Correct integer equation, wrong quotient/remainder: 1665*1024=1664*1024+1024.
    let _ = decompression_relation::<10>(
        std::hint::black_box(512),
        std::hint::black_box(1664),
        std::hint::black_box(1024),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_decompression_negative_remainder_alias() {
    // Correct native-field equation 512=1024-512, but no integer remainder.
    let _ = decompression_relation::<10>(
        std::hint::black_box(0),
        std::hint::black_box(1),
        std::hint::black_box(-512),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_decompression_output_overflow() {
    let _ = decompression_relation::<10>(
        std::hint::black_box(0),
        std::hint::black_box(4096),
        std::hint::black_box(512),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_decompression_input_overflow() {
    let _ = decompression_relation::<10>(
        std::hint::black_box(1024),
        std::hint::black_box(3329),
        std::hint::black_box(512),
    );
}
#[test(should_fail_with = "decompression relation does not hold")]
fn rejects_decompression_wrong_equation() {
    let _ = decompression_relation::<10>(
        std::hint::black_box(0),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_decompression_fractional_output_alias() {
    // All other checks hold:512=1024*(1/2)+0 in the native field.
    // The explicit12-bit output range is essential to exclude this fraction.
    let _ = decompression_relation::<10>(
        std::hint::black_box(0),
        std::hint::black_box((1 as Field) / 2),
        std::hint::black_box(0),
    );
}

fn fused_inverse_compression_boundaries<let D: u32>() {
    for kind in 0..4 {
        let mut a = [0u32; 256];
        let mut b = [0u32; 256];
        let mut c = [0u32; 256];
        for i in 0..256 {
            a[i] = if kind == 0 {
                0
            } else if kind == 1 {
                3328
            } else if kind == 2 {
                if i % 2 == 0 {
                    0
                } else {
                    3328
                }
            } else {
                (i * i * 13 + 997 * i) % 3329
            };
            b[i] = if kind == 0 { 0 } else { 3328 };
            c[i] = if kind < 2 { 0 } else { 3328 };
        }
        let a = std::hint::black_box(a);
        let b = std::hint::black_box(b);
        let c = std::hint::black_box(c);
        assert(inverse_ntt_compress_add::<D>(a, b, c) == compress::<D>(inverse_ntt_add(a, b, c)));
    }
    // Zero inverse input isolates every important compression rounding boundary
    // in the additive output, including the quotient increment at final wrap.
    let values: [u32; 15] =
        [0, 1, 2, 104, 105, 832, 833, 1664, 1665, 2496, 2497, 3224, 3225, 3327, 3328];
    let mut b = [0u32; 256];
    for i in 0..256 {
        b[i] = values[i % 15];
    }
    let b = std::hint::black_box(b);
    assert(inverse_ntt_compress_add::<D>([0; 256], b, [0; 256]) == compress::<D>(b));
}
#[test]
fn constrained_fused_inverse_compression() {
    fused_inverse_compression_boundaries::<4>();
    fused_inverse_compression_boundaries::<10>();
}
#[test]
unconstrained fn hint_fused_inverse_compression() {
    fused_inverse_compression_boundaries::<4>();
    fused_inverse_compression_boundaries::<10>();
}
unconstrained fn exhaustive_fused_compression_hint<let D: u32>() {
    let highs: [u32; 4] = [0, 1, 1000, 26000];
    for i in 0..4 {
        for a in 0..3329 {
            let x = 3329 * highs[i] + a;
            assert(
                compress_unreduced::<D, 15>(x as Field)
                    == (((1 << D) * a + 1664) / 3329) % (1 << D),
            );
        }
    }
    let x = 88614656u64;
    assert(
        compress_unreduced::<D, 15>(x as Field)
            == ((((1u64 << (D as u64)) * (x % 3329) + 1664) / 3329) % (1u64 << (D as u64))) as u32,
    );
}
#[test]
unconstrained fn exhaustive_fused_compression_hints() {
    exhaustive_fused_compression_hint::<4>();
    exhaustive_fused_compression_hint::<10>();
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_fractional_high() {
    let _ = compression_relation_bounded::<10, 15>(
        std::hint::black_box(1664),
        std::hint::black_box(0),
        std::hint::black_box((1664 as Field) / (3329 * 1024)),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_fractional_low() {
    let _ = compression_relation_bounded::<10, 15>(
        std::hint::black_box(1664),
        std::hint::black_box((1664 as Field) / 3329),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_negative_remainder() {
    let _ = compression_relation_bounded::<10, 15>(
        std::hint::black_box(1664),
        std::hint::black_box(1),
        std::hint::black_box(0),
        std::hint::black_box(-1665),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_noncanonical_remainder() {
    let _ = compression_relation_bounded::<10, 15>(
        std::hint::black_box(3329),
        std::hint::black_box(0),
        std::hint::black_box(0),
        std::hint::black_box(3329),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_low_overflow() {
    let _ = compression_relation_bounded::<4, 15>(
        std::hint::black_box(3329 * 16),
        std::hint::black_box(16),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_fused_compression_high_overflow() {
    let _ = compression_relation_bounded::<4, 15>(
        std::hint::black_box(3329 * 16 * 32768),
        std::hint::black_box(0),
        std::hint::black_box(32768),
        std::hint::black_box(0),
    );
}

// Exercise the actual row maximum with canonical factors selected by sign.
// A negative centered coefficient reaches its maximum at input 0; a positive
// one reaches its maximum at input 3328. No random sampling is needed here.
fn row_width_boundaries<let D: u32, let ROWS: u32>(inverse: bool) {
    let stride = if inverse { 16 } else { 2 };
    let blocks = 256 / (16 * stride);
    for selected in 0..ROWS {
        let row = if ROWS == 2 {
            if selected == 0 {
                0
            } else {
                8
            }
        } else {
            selected
        };
        let mut a = [0u32; 256];
        let mut maxima = [0u64; 16];
        for block in 0..blocks {
            let matrix = transform_matrix::<3, 4, 16>(block, inverse);
            let mut correction = 0u32;
            for column in 0..16 {
                let coefficient = matrix[row][column];
                let negative = coefficient > 1664;
                let magnitude = if negative {
                    3329 - coefficient
                } else {
                    coefficient
                };
                if negative {
                    correction += magnitude;
                }
                maxima[block] += magnitude as u64 * 3328;
                for offset in 0..stride {
                    a[block * 16 * stride + column * stride + offset] =
                        if negative { 0 } else { 3328 };
                }
            }
            maxima[block] += (correction % 3329) as u64;
            if inverse {
                maxima[block] += 6656;
            }
        }
        let addend = if inverse { [3328u32; 256] } else { [0u32; 256] };
        let out = transform_stages_output::<3, 4, 16, D>(
            std::hint::black_box(a),
            inverse,
            std::hint::black_box(addend),
            std::hint::black_box(addend),
        );
        for block in 0..blocks {
            let expected = if D == 0 {
                (maxima[block] % 3329) as u32
            } else {
                ((((1u64 << D as u64) * (maxima[block] % 3329) + 1664) / 3329) % (1u64 << D as u64))
                     as u32
            };
            for offset in 0..stride {
                assert(out[block * 16 * stride + row * stride + offset] == expected);
            }
        }
    }
}
#[test]
fn constrained_row_width_maxima() {
    row_width_boundaries::<0, 2>(false);
    row_width_boundaries::<0, 2>(true);
    row_width_boundaries::<4, 2>(true);
    row_width_boundaries::<10, 2>(true);
    // The exact largest integer admitted by a 14-bit quotient must pass.
    let x = std::hint::black_box((3329u64 << 14) - 1);
    assert(divrem::<14>(x as Field) == (16383, 3328));
    assert(
        compression_relation_bounded::<10, 14>(
            std::hint::black_box((3329 as Field) * 1024 * 16383 + 1664),
            std::hint::black_box(0),
            std::hint::black_box(16383),
            std::hint::black_box(1664),
        )
            == 0,
    );
    assert(compress_unreduced::<10, 14>(std::hint::black_box(3328)) == 0);
    assert(compress_unreduced::<4, 14>(std::hint::black_box(3328)) == 0);
}
#[test]
unconstrained fn hint_row_width_maxima() {
    row_width_boundaries::<0, 16>(false);
    row_width_boundaries::<0, 16>(true);
    row_width_boundaries::<4, 16>(true);
    row_width_boundaries::<10, 16>(true);
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_row_width_quotient_overflow() {
    // Equation and remainder are valid; only the narrowed quotient rejects.
    let _ = division_relation::<14>(
        std::hint::black_box(3329 * 16384),
        std::hint::black_box(16384),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_row_width_fractional_quotient() {
    let _ = division_relation::<14>(
        std::hint::black_box(1),
        std::hint::black_box((1 as Field) / 3329),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_row_width_high_overflow() {
    // Equation, compressed output and remainder are valid; only H = 14 rejects.
    let _ = compression_relation_bounded::<10, 14>(
        std::hint::black_box((3329 as Field) * 1024 * 16384),
        std::hint::black_box(0),
        std::hint::black_box(16384),
        std::hint::black_box(0),
    );
}
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_row_width_fractional_high() {
    let _ = compression_relation_bounded::<10, 14>(
        std::hint::black_box(1664),
        std::hint::black_box(0),
        std::hint::black_box((1664 as Field) / (3329 * 1024)),
        std::hint::black_box(0),
    );
}
