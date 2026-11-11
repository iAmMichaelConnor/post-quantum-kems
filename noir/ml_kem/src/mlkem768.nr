/// Final FIPS 203 ML-KEM-768.
/// All random seeds must be sampled uniformly by the caller.
pub fn keygen(d: [u8; 32], z: [u8; 32]) -> ([u8; 1184], [u8; 2400]) {
    lattice_kem_core::kem::mlkem_keygen::<3>(d, z)
}
/// Encapsulate to `pk`. ML-KEM rejects non-canonical pk coefficients
/// (FIPS 203 Section 7.2). Bind the exact registered pk bytes or H(pk) in the
/// calling circuit; this call does not identify the recipient.
pub fn encapsulate(pk: [u8; 1184], entropy: [u8; 32]) -> ([u8; 1088], [u8; 32]) {
    lattice_kem_core::kem::mlkem_encapsulate::<3>(pk, entropy)
}
/// Decapsulate with an expanded key `sk = sk_PKE || pk || H(pk) || z`.
/// The proof does not bind the recipient: any sk_PKE that decrypts `ct` (one
/// can be built from the message alone) or any z' is accepted. Use
/// `decapsulate_from_seeds` to bind the result to a registered pk.
pub fn decapsulate(sk: [u8; 2400], ct: [u8; 1088]) -> [u8; 32] {
    lattice_kem_core::kem::mlkem_decapsulate::<3>(sk, ct)
}
/// Seed-form decapsulation: derive (pk, sk) from (d, z) as `keygen` does, then
/// decapsulate `ct`. Returns (pk, shared_key). Assert that pk (or H(pk)) equals
/// the registered key to prove that its holder obtains shared_key for any `ct`
/// that passes re-encryption. pk does not bind z, which selects only the
/// implicit-rejection key; commit to z at key registration if that key must be
/// bound too.
pub fn decapsulate_from_seeds(d: [u8; 32], z: [u8; 32], ct: [u8; 1088]) -> ([u8; 1184], [u8; 32]) {
    lattice_kem_core::kem::mlkem_decapsulate_from_seeds::<3>(d, z, ct)
}
