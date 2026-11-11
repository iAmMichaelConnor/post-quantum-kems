//! Round-three Kyber-512 (`kyber512`) and Kyber-768 (`kyber768`), the SHA3/SHAKE
//! variant of specification v3.02. Use it only where round-three compatibility
//! is required: its entropy hashing, final KDF, implicit rejection and public-key
//! decoding differ from ML-KEM, and it accepts alias public keys. See
//! docs/CORRECTNESS.md.
pub mod kyber512;
pub mod kyber768;
mod vectors;
mod kyber_kats;
mod benchmarks;
