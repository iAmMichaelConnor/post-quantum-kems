// Benchmark entry points: one #[export] function per operation and parameter set.
// `nargo export` compiles each to its own program for the gates report.

#[export]
fn kyber512_keygen(d: [u8; 32], z: [u8; 32]) -> ([u8; 800], [u8; 1632]) {
    crate::kyber512::keygen(d, z)
}

#[export]
fn kyber512_encapsulate(pk: [u8; 800], entropy: [u8; 32]) -> ([u8; 768], [u8; 32]) {
    crate::kyber512::encapsulate(pk, entropy)
}

#[export]
fn kyber512_decapsulate(sk: [u8; 1632], ct: [u8; 768]) -> [u8; 32] {
    crate::kyber512::decapsulate(sk, ct)
}

#[export]
fn kyber768_keygen(d: [u8; 32], z: [u8; 32]) -> ([u8; 1184], [u8; 2400]) {
    crate::kyber768::keygen(d, z)
}

#[export]
fn kyber768_encapsulate(pk: [u8; 1184], entropy: [u8; 32]) -> ([u8; 1088], [u8; 32]) {
    crate::kyber768::encapsulate(pk, entropy)
}

#[export]
fn kyber768_decapsulate(sk: [u8; 2400], ct: [u8; 1088]) -> [u8; 32] {
    crate::kyber768::decapsulate(sk, ct)
}
