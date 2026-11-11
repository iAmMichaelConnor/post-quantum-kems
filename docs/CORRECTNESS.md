# Correctness contract

What the KEM circuits prove, the input domains they accept, the compiler and
backend premises they rest on, and what a calling circuit must add. Arithmetic
and hash bounds are in [OPTIMISATIONS.md](OPTIMISATIONS.md).

## API and domains

`ml_kem::mlkem512`, `ml_kem::mlkem768`, `kyber::kyber512` and `kyber::kyber768`
each provide:

- `keygen(d, z) -> (public_key, decapsulation_key)` with two 32-byte seeds;
- `encapsulate(public_key, entropy) -> (ciphertext, shared_key)`;
- `decapsulate(decapsulation_key, ciphertext) -> shared_key`;
- `decapsulate_from_seeds(d, z, ciphertext) -> (public_key, shared_key)`.

| Variant | Public key | Expanded secret key | Ciphertext | NIST category |
|---|---:|---:|---:|---:|
| Kyber-512 / ML-KEM-512 | 800 | 1,632 | 768 | 1 |
| Kyber-768 / ML-KEM-768 | 1,184 | 2,400 | 1,088 | 3 |

Shared keys are 32 bytes. Array types enforce encoded lengths. ML-KEM is final
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) (Algorithms
16 to 18 with the input checks of Sections 7.2 and 7.3), not its draft. Kyber is
the round-three SHA3/SHAKE variant
([specification v3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf),
Algorithms 7 to 9), not Kyber-90s. The 1024 parameter sets are not implemented:
their noise, compression and completeness bounds differ.

These are full KEMs: SHAKE-generated matrix and noise, ciphertext compression,
the re-encryption check and the prescribed implicit-rejection key. The prover
selects no noise. Seeds and entropy are caller inputs; a circuit cannot prove
that they are uniform or fresh. Witness generation is not constant time.

The internal core `lattice_kem_core` exposes only scheme-named entry points
(`kem::mlkem_*`, `kem::kyber_*`). Its scheme selector is private, because a
witness-valued selector would let a prover switch off the ML-KEM checks. For
the same reason, do not choose between scheme entry points on a witness value.
`scripts/check-core-visibility.sh` checks the visibility with `nargo check`.

## Variant differences

| | ML-KEM | Round-three Kyber |
|---|---|---|
| Key generation | G(d ‖ rank) | G(d) |
| Encapsulation message | entropy | SHA3-256(entropy) |
| Shared key | first half of G(m ‖ H(pk)) | SHAKE256(K̄ ‖ H(ct)) |
| Invalid ciphertext | SHAKE256(z ‖ ct) | SHAKE256(z ‖ H(ct)) |
| Public-key coefficients at encapsulation | must be below 3329 | reduced modulo 3329 |
| Stored H(pk) at decapsulation | checked | not checked |

Both return a key for every correctly sized ciphertext, including all-zero and
modified ciphertexts. Rejection is a constrained selection between the two
keys, never an assertion that the ciphertext re-encrypts. ML-KEM decapsulation
checks the stored hash only; during re-encryption it decodes the stored public
key modulo 3329, so a hash-consistent key with alias coefficients is accepted,
as FIPS 203 Section 7.3 permits.

## Binding keys in a circuit

The KEM relations do not identify a recipient. The calling circuit must:

- **Sender:** bind the exact registered public-key bytes, or SHA3-256 of those
  bytes. Never bind decoded or reduced coefficients. Kyber accepts a key with a
  coefficient `c + 3329 <= 4095` (an alias); its shared key differs from the
  one the holder of the canonical key derives. ML-KEM rejects aliases; prefer
  it for new integrations.
- **Recipient, `decapsulate`:** binds neither the recipient nor the result. The
  prover supplies the whole expanded key. Even with pk and H(pk) bound, the
  prover can choose another z and return its rejection key, and anyone who
  knows the message can build an sk_PKE that decrypts the ciphertext. Kyber does
  not check H(pk) at all.
- **Recipient, `decapsulate_from_seeds`:** derives the key pair from `(d, z)`
  as `keygen` does and returns the public key with the shared key. Asserting
  that the returned public key (or its hash) equals the registered key proves
  that the holder of that key obtains the shared key for any ciphertext that
  passes re-encryption. The public key does not bind z, which selects only the
  implicit-rejection key; commit to z at registration if that key must be bound.

KEM outputs alone establish neither note ownership nor application
authorization.

## Sampling and completeness

The circuit checks the full first 840 bytes of each SHAKE128 matrix expansion
and accepts the first 256 candidates below 3329, in order. This is 280
three-byte iterations, the bounded implementation that FIPS 203 Appendix B
permits. Exhaustion fails with `SampleNTT exhausted`; it does not zero-fill,
change the matrix or return an implicit-rejection key. The standard bounds the
exhaustion probability below 2^-261 under its XOF assumptions.

Round-three Kyber specifies an unbounded parser. This implementation shares
the 840-byte bound, so its Kyber compatibility excludes the inputs that exhaust
it.

Secret and error coefficients come from the constrained centred-binomial
sampler over SHAKE256 output. Tests accept a stream whose last coefficient
appears in iteration 280 and reject a stream with no acceptable coefficient.

## Hints

Brillig hints supply division quotients and remainders, compression quotients,
decoded digits, rejection flags and the selected SampleNTT indices. Every hint
output is range-checked and tied to its input by an exact integer relation; the
bounds that keep those relations below the field modulus are in
[OPTIMISATIONS.md](OPTIMISATIONS.md). Tests exercise dishonest hints against
the relation and honest hint generation over the boundary inputs separately: a
rejected false hint does not show that every valid input gets a usable hint.

## Backend and compiler premises

In the compiled circuit, three bounds in `lattice_kem_core` come from the ACIR
memory bound `index < table length`, not from a RANGE gate. The compilers
checked (Noir 1.0.0, 275d3ab1, and 1.0.0-rc.3, 5a7ee9bf; the optimiser source is
identical) delete a RANGE on a witness that is also a memory index when the
RANGE is not stricter than `ceil(log2(length))` bits. They also delete the
16-bit range of a `u16` hint output in the same way. The bound that remains is
enforced by the backend; see [memory index bounds](#memory-index-bounds).

| Value | Source range check | Memory read that bounds it | Bound in the circuit |
| --- | --- | --- | --- |
| CBD noise word, ETA 2 or 3 | `assert_max_bit_size::<D>` with D = 4 or 6 in `sampling::check_words`, again in `sampling::cbd_lookup` | `cbd_lookup` table of `T = 2^(2*ETA)` entries | word < 16 or < 64 |
| Decoded coefficient for D = 1 (message) and D = 4 (`v`) | `assert_max_bit_size::<D>` in `poly::pack_coefficients` | `poly::decompress_lookup` table of `N = 2^D` entries, called from `pke::encrypt` and `pke::decrypt` | coefficient < 2 or < 16 |
| SampleNTT index | `u16` hint output of `sampling::parse_candidates_hint` | `records[indices[j]]` in `sampling::check_candidates`, 560 records | index < 560 |

The tables are exactly as long as the intended bound. `assert(T == 1 << (2 * ETA))`
in `cbd_lookup` and `assert(N == 1 << D)` in `decompress_lookup` fix this at
compile time; keep them. Therefore the `check_words` repacking (below 2^192)
and the `pack_coefficients` packing (below 2^96) stay exact integer identities
below the BN254 scalar field modulus
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
Any SampleNTT index below 560 is then fixed by `check_record`.

The premise holds for bb 6.0.0 (aztec-packages 0219f11d81). Show it again for
any other backend before proving there.

What the Noir tests show: `rejects_out_of_bounds_candidate_index` passes index
560 through `std::hint::black_box`, so the read is not folded at compile time,
and execution stops in the ACVM memory solver ("Index out of bounds"), not in a
constraint. `rejects_noise_word_overflow` calls `check_words` on black-boxed
words without a table read, so there the 6-bit range check is kept and ACVM
rejects the word ("call to assert_max_bit_size"). Both are execution results,
not constraint checks or proofs.

Keep the source range checks. They are the bound wherever a value is not also
used as a table index, and a refactor that removes the table read must not
remove the bound.

### Memory index bounds

Citations are `file:line` at aztec-packages 0219f11d81 (bb 6.0.0) and Noir
5a7ee9bf (1.0.0-rc.3); bb paths are under `barretenberg/cpp/src/barretenberg/`,
Noir paths under `acvm-repo/acvm/src/`. The cited Noir files are byte-identical
at Noir 1.0.0 (275d3ab1).

The compiler's range optimiser treats the index of every ACIR memory read or
write as bounded by `ceil(log2(length))` bits and deletes any explicit RANGE on
that witness that is not stricter (`compiler/optimizers/redundant_range.rs:159-169`,
`:293-297`; removal at `:226-283`). The only remaining bound is then
`index < length`, which bb enforces as follows. A read-only block becomes a
single-value ROM table checked by LogUp: one table row per index with the index
as a circuit constant (`stdlib_circuit_builders/rom_ram_logic.cpp:40-70`), one
read row per access (`:105-128`), the array id in `q_c` (`:233`), and the read
counts set at finalisation (`:359-388`). The memory relation sums `1/denom` over
read rows and `-m_i/denom` over table rows with
`denom = gamma + index + eta*value + eta^2*array_id`
(`relations/memory_relation.hpp:298-358`). A read whose index matches no table
row leaves a pole that no table row cancels, so it fails except with negligible
probability over the challenges. A block with a write becomes a RAM table
(`dsl/acir_format/acir_to_constraint_buf.cpp:1045-1053`); its sorted chain is
pinned to index 0 (`rom_ram_logic.cpp:646-657`) and to `length - 1`
(`:574-601`). ACIR blocks use single-value tables
(`dsl/acir_format/block_constraint.cpp:100-122`). An arithmetisation without
memory gates refuses ROM and RAM blocks (`block_constraint.cpp:73-85`). bb's
honest circuit builder also refuses an out-of-range index
(`stdlib/primitives/memory/rom_table.cpp:168`, `ram_table.cpp:179`, `:224`), and
ACVM refuses it during execution (`pwg/memory_op.rs:44-51`, `:76-88`, `:61-62`);
neither of those is a constraint.

## Aztec integration

The library provides KEM relations, not an Aztec message format or
note-delivery adapter. A sender circuit can encapsulate to a registered
recipient key and use the shared secret for payload encryption; recipient
decapsulation normally runs outside a circuit. An integration must specify:

- Recipient key registration and discovery, binding keys as above.
- KEM ciphertext packing and transport. Keys and ciphertexts are hundreds of
  bytes, not replacements for an Aztec address or a Grumpkin coordinate.
- Application-domain-separated key derivation and the header/body key and IV
  format. Deriving only an AES key from the raw shared secret is not a complete
  encryption scheme; CBC needs a fresh unpredictable IV.
- Receiver-side validation of the recovered note against its committed hash and
  transaction context. The intended composition relies on that validation
  rather than a MAC; it is not general-purpose authenticated encryption.
- The privacy and public-input policy of the enclosing circuit.

```rust
let (kem_ciphertext, shared) = mlkem768::encapsulate(recipient_key, entropy);
// Derive aes_key with application context and the selected message format.
let ciphertext = std::aes128::aes128_encrypt(plaintext, iv, aes_key);
```

Large witness data can reach a contract through Aztec capsules
(`oracle/capsules.nr::load`) instead of private arguments. A capsule's presence
does not authenticate its contents: constrain every value read from it.

## Test references

- ML-KEM: the NIST ACVP final-FIPS-203 key-generation and
  encapsulation/decapsulation samples in `reference/nist-acvp/`
  (`REVISION` names the ACVP-Server commit, `SHA256SUMS` the files). These tests
  are not NIST certification.
- Kyber: the published round-three KATs `PQCkemKAT_1632.rsp` and
  `PQCkemKAT_2400.rsp` in `reference/kyber-py/`.
- Both: known-answer, implicit-rejection, seed-form and alias vectors computed
  by the vendored [kyber-py](https://github.com/GiacomoPope/kyber-py) reference
  in `reference/kyber-py/src/`, at the commit in its `REVISION`.

The generators in `scripts/` write the Noir test modules from these inputs;
run each with `--check` to verify that the committed modules match (CI does).
