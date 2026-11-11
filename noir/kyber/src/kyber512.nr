/// Round-three Kyber-512.
/// All random seeds must be sampled uniformly by the caller.
pub fn keygen(d: [u8; 32], z: [u8; 32]) -> ([u8; 800], [u8; 1632]) {
    lattice_kem_core::kem::kyber_keygen::<2>(d, z)
}
/// Encapsulate to `pk`. Round-three Kyber decodes pk coefficients modulo q,
/// so an alias pk (a coefficient c + 3329 <= 4095) is accepted and gives a key
/// the holder of the canonical pk never derives. Bind the exact registered pk
/// bytes or SHA3-256(pk) in the calling circuit, never decoded or reduced
/// coefficients. Prefer ML-KEM, which rejects aliases, for new integrations.
pub fn encapsulate(pk: [u8; 800], entropy: [u8; 32]) -> ([u8; 768], [u8; 32]) {
    lattice_kem_core::kem::kyber_encapsulate::<2>(pk, entropy)
}
/// Decapsulate with an expanded key `sk = sk_PKE || pk || H(pk) || z`.
/// Kyber does not check H(pk). The proof does not bind the recipient: any
/// sk_PKE that decrypts `ct` (one can be built from the message alone) or any
/// z' is accepted. Use `decapsulate_from_seeds` to bind the result to a
/// registered pk.
pub fn decapsulate(sk: [u8; 1632], ct: [u8; 768]) -> [u8; 32] {
    lattice_kem_core::kem::kyber_decapsulate::<2>(sk, ct)
}
/// Seed-form decapsulation: derive (pk, sk) from (d, z) as `keygen` does, then
/// decapsulate `ct`. Returns (pk, shared_key). Assert that pk (or H(pk)) equals
/// the registered key to prove that its holder obtains shared_key for any `ct`
/// that passes re-encryption. pk does not bind z, which selects only the
/// implicit-rejection key; commit to z at key registration if that key must be
/// bound too.
pub fn decapsulate_from_seeds(d: [u8; 32], z: [u8; 32], ct: [u8; 768]) -> ([u8; 800], [u8; 32]) {
    lattice_kem_core::kem::kyber_decapsulate_from_seeds::<2>(d, z, ct)
}
