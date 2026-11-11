//! Rank-generic K-PKE, the ML-KEM and Kyber transforms, NTT, sampling and codecs
//! shared by `ml_kem` and `kyber`. Applications should depend on one of those;
//! this package exposes only scheme-named entry points.
pub mod sponge;
mod poly;
mod sampling;
mod pke;
pub mod kem;
mod tests;
mod acvp_decode_tests;
