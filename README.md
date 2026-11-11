> [!WARNING]
> **This code has not been audited.** It is experimental software, provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A bug can leave a circuit under-constrained, so that invalid proofs are accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

# post-quantum-kems

**Post-quantum key exchange inside a Noir circuit.** Establish a shared secret
that a quantum computer cannot recover, and prove you did it honestly.

For example, you can:

- Prove a key pair was generated correctly from its seeds.
- Prove a ciphertext encapsulates a shared key to a particular public key.
- Prove you can decapsulate a ciphertext, and what shared key comes out.
- Prove the shared key belongs to the holder of a registered public key.
- Hash with SHA3 and SHAKE in circuit.

**In an Aztec contract you will probably only need constrained encapsulation.**
A sender's private function calls `encapsulate` to prove that the ciphertext it
publishes really is addressed to the recipient's registered public key, so the
recipient is guaranteed to be able to recover the shared key. The recipient
generates keys and decapsulates off chain, in their own wallet, where nothing
needs proving. Constrained key generation and decapsulation are here for the
rarer designs that must prove those steps too.

These are Noir implementations of **FIPS 203 ML-KEM-512/768** and **round-three
Kyber-512/768**: constrained key generation, encapsulation and decapsulation,
including the SHAKE-generated matrix and noise, ciphertext compression, the
re-encryption check and implicit rejection. Payload encryption is not included.

## What is in the repository

| Package | Contents |
| --- | --- |
| [`ml_kem`](noir/ml_kem) | `mlkem512`, `mlkem768` |
| [`kyber`](noir/kyber) | `kyber512`, `kyber768` |
| [`fips202`](noir/fips202) | SHA3 and SHAKE sponges (byte, lane and word inputs) |
| [`lattice_kem_core`](noir/lattice_kem_core) | Shared implementation of the two KEM packages; not an application API |

Use ML-KEM unless you need round-three Kyber compatibility.

## Compatibility

The Noir packages are tested with Noir 1.0.0-rc.3, the minimum supported
version (what Aztec 6.0.0 ships), and with Noir 1.0.0, the latest release, on
every pull request, and with Noir nightly every night. Keep this in sync with
the `toolchain` matrix in `.github/workflows/test.yml`.

## Installation

In your `Nargo.toml`, add the packages you need. Each lives in its own
directory of this repository:

```toml
[dependencies]
ml_kem = { git = "https://github.com/iAmMichaelConnor/post-quantum-kems", tag = "v0.1.0", directory = "noir/ml_kem" }
kyber = { git = "https://github.com/iAmMichaelConnor/post-quantum-kems", tag = "v0.1.0", directory = "noir/kyber" }
fips202 = { git = "https://github.com/iAmMichaelConnor/post-quantum-kems", tag = "v0.1.0", directory = "noir/fips202" }
```

## Usage

### `ml_kem` and `kyber`

`mlkem512`, `mlkem768`, `kyber512` and `kyber768` each provide the same four
functions:

```rust
use ml_kem::mlkem768;

// d and z are independent uniform 32-byte seeds; entropy is 32 fresh bytes.
let (pk, sk) = mlkem768::keygen(d, z);
let (ct, sender_key) = mlkem768::encapsulate(pk, entropy);
let receiver_key = mlkem768::decapsulate(sk, ct);
assert(sender_key == receiver_key);

// Recipient-bound form: derive the key pair from the seeds and bind its pk.
let (derived_pk, bound_key) = mlkem768::decapsulate_from_seeds(d, z, ct);
assert(derived_pk == pk);
```

| Parameter set | Public key | Secret key | Ciphertext | NIST category |
| --- | ---: | ---: | ---: | ---: |
| `mlkem512`, `kyber512` | 800 | 1632 | 768 | 1 |
| `mlkem768`, `kyber768` | 1184 | 2400 | 1088 | 3 |

Shared keys are 32 bytes. Kyber differs from ML-KEM in entropy hashing, the
final key derivation, implicit rejection and public-key decoding; see
[variant differences](docs/CORRECTNESS.md#variant-differences).

### `fips202`

```rust
let digest: [u8; 32] = fips202::h(input); // SHA3-256
let wide: [u8; 64] = fips202::g(input); // SHA3-512
let stream: [u8; 840] = fips202::shake128(input);
let out: [u8; 32] = fips202::shake256(input);
```

`sponge`, `sponge_lanes` and `sponge_words` take the rate and domain suffix as
compile-time generics; any pair other than a FIPS 202 instance fails to compile.

## Benchmarks

Circuit size (`bb gates` `circuit_size`, before power-of-two padding) of each
operation's `#[export]` benchmark function, measured with Noir 1.0.0 and bb
6.0.0 on 2026-11-10. The [benchmark workflow](.github/workflows/benchmark.yml)
reports current numbers on every pull request and records history on the
`gh-pages` branch.

| Parameter set | keygen | encapsulate | decapsulate |
| --- | ---: | ---: | ---: |
| ML-KEM-512 | 676,549 | 664,300 | 807,365 |
| ML-KEM-768 | 1,182,485 | 1,203,898 | 1,412,935 |
| Kyber-512 | 676,549 | 806,328 | 716,454 |
| Kyber-768 | 1,182,485 | 1,399,610 | 1,267,888 |

To generate the reports locally:

```bash
./scripts/build-gates-report.sh
nargo export --workspace --force-brillig && ./scripts/build-brillig-report.sh
```

## Security

If you find a vulnerability, please **do not** open a public issue. Report it
privately via [GitHub's "Report a vulnerability"](https://github.com/iAmMichaelConnor/post-quantum-kems/security/advisories/new)
form instead.

- **Bind keys, not calls.** A sender circuit must bind the exact registered
  public-key bytes, or SHA3-256 of them, never decoded coefficients: Kyber
  accepts alias public keys whose holder derives a different shared key.
- **`decapsulate` binds neither the recipient nor the returned key.** The prover
  supplies the whole expanded secret key. Use `decapsulate_from_seeds` and
  assert that the returned public key is the registered one.
- **Randomness is an input.** A circuit cannot prove that seeds or entropy are
  uniform or fresh. Witness generation is not constant time.
- **Bounded matrix sampling.** Each matrix polynomial reads 840 SHAKE128 bytes,
  the bound FIPS 203 Appendix B permits; exhaustion fails rather than
  falling back. Kyber compatibility excludes inputs that exhaust it.
- **Backend premise.** Three range bounds rely on the backend's memory-index
  check; this holds for bb 6.0.0 and must be re-shown for other backends.

The [correctness contract](docs/CORRECTNESS.md) states the accepted domains,
key binding, hint soundness, backend premises and Aztec integration notes.
[OPTIMISATIONS.md](docs/OPTIMISATIONS.md) covers the arithmetic and hash
bounds. Known-answer tests come from NIST ACVP vectors and the
[kyber-py](https://github.com/GiacomoPope/kyber-py) reference; see
[NOTICE](NOTICE).

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
