# Arithmetic and hash implementation

ML-KEM and Kyber share the rank-generic implementation in
[`lattice_kem_core`](../noir/lattice_kem_core/src/lib.nr).
The supported modulus is 3329 and polynomial degree is 256. The public wrappers
fix the scheme and rank; these bounds do not authorize arbitrary parameter sets.

## Canonical coefficients and exact division

Polynomial operations consume coefficients in `0..3329`. Hints supply division
quotients and remainders; constraints range-check both and enforce
`x = quotient * 3329 + remainder`, with `remainder < 3329`.
The operand bounds keep these equations below the native field modulus, so
native-field equality is also integer equality. A hint cannot select another
remainder or bypass rejection sampling.

## Centered transform rows

[`poly.nr`](../noir/lattice_kem_core/src/poly.nr) constructs transform
matrices at compile time. A centered coefficient `c >= 0` contributes `c*a`;
a negative coefficient `-d` contributes `d*(3328-a)` plus the modular correction.
For canonical inputs, the exact row maximum is

```text
3328 * sum(abs(centered coefficients)) + correction + maximum_addends
correction = sum(negative magnitudes) mod 3329
```

Choosing 3328 for positive coefficients and zero for negative coefficients
attains that maximum. The final inverse stage includes both additive
polynomials, contributing at most 6656 after scaling. The coefficient matrix
and the bound come from the same compile-time data.

For groups of at most 128 terms the bound is below `2^30`. The final 16-term
inverse group is at most 88,614,656; its D=4/10 compression numerator is below
`2^37`. Bound calculations use u64.

A final transform row uses a 14-bit quotient when
`floor(maximum/3329) < 2^14`; remaining final rows use 15 bits.
Of the final forward outputs, 248 use 14 bits and eight need 15.
For final inverse/compression, 112 fit 14 bits or fewer and 144 need 15.
The dispatch is compile-time; it does not assume exceptional canonical inputs
are unreachable.

## Fused inverse and compression

The inverse transform incorporates its additive polynomials before reduction.
Compression constrains the rounded quotient rather than reducing and then
rounding in separate circuits:

```text
rounded = floor((2^D * x + 1664) / 3329)
compressed = rounded mod 2^D
high = floor(rounded / 2^D)
```

The high quotient uses 14 bits only when the exact maximum satisfies
`floor(floor((2^D*maximum+1664)/3329)/2^D) < 2^14`; otherwise it uses 15.
Keep the rounded endpoint `rounded = 2^D`: masking implements the required
wrap to zero. Removing it changes the accepted compression boundary.

## Sampling records and lookup tables

[`sampling.nr`](../noir/lattice_kem_core/src/sampling.nr) checks the
first 256 accepted candidates in the full 840-byte SHAKE128 matrix stream.
Prefix records establish candidate order and acceptance; selected indices
cannot skip an earlier accepted candidate. Exhaustion rejects explicitly.
CBD tables fix the small noise distribution. Decompression and message tables
preserve their exact coefficient ranges. See
[backend premises](CORRECTNESS.md#backend-and-compiler-premises) for the memory-index checks that enforce lookup bounds.

## Packing and hash lanes

For eight bytes, `sum(byte[j]*256^j) <= 2^64-1`, below the native field modulus.
The lane path asserts this bound before converting to u64. Endianness, suffix,
padding and lengths remain part of the hash relation.
[`fips202`](../noir/fips202/src/lib.nr) shares its sponge core across byte, word
and lane APIs and uses the compiler's Keccak permutation blackbox. Raw sponge
entrypoints require supported constant rates and domain suffixes.

Arithmetic boundaries and hint-corruption cases are exercised by the core tests;
byte, lane, rate and hash boundary cases live in the `fips202` tests.

## Hash schedule of encapsulation

Every matrix polynomial expands the full 840-byte SHAKE128 stream (five rate
blocks). The permutation counts follow from the fixed input lengths and FIPS
202 padding; they are not backend gate measurements.

| Stage | ML-KEM-512 | Kyber512 | ML-KEM-768 | Kyber768 |
| --- | ---: | ---: | ---: | ---: |
| Public-key hash | 6 | 6 | 9 | 9 |
| G(message and public-key hash) | 1 | 1 | 1 | 1 |
| Matrix SHAKE128 expansion | 20 | 20 | 45 | 45 |
| Noise SHAKE256 expansion | 7 | 7 | 7 | 7 |
| Entropy hash | 0 | 1 | 0 | 1 |
| Ciphertext hash | 0 | 6 | 0 | 9 |
| Final key derivation | 0 | 1 | 0 | 1 |
| **Keccak permutations** | **34** | **42** | **62** | **73** |

Kyber768 hashes a 1088-byte ciphertext: eight complete SHA3-256 rate blocks
plus a padding block. Expanding fewer than five SHAKE128 blocks per matrix
polynomial would change the accepted sampling domain; see
[sampling and completeness](CORRECTNESS.md#sampling-and-completeness).
