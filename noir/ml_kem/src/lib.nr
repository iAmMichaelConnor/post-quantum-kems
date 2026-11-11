//! FIPS 203 ML-KEM-512 (`mlkem512`) and ML-KEM-768 (`mlkem768`): constrained
//! key generation, encapsulation and decapsulation, including the input checks
//! of FIPS 203 Sections 7.2 and 7.3. Seeds and entropy are caller inputs; a
//! circuit cannot prove they are uniform. See docs/CORRECTNESS.md for the
//! accepted domains and how a calling circuit must bind keys.
pub mod mlkem512;
pub mod mlkem768;
mod vectors;
mod acvp_tests;
mod alias_tests;
mod benchmarks;
