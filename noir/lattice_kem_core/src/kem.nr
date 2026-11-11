// ML-KEM: FIPS 203 Sections 6.1--6.3 (Algorithms 16--18), with input
// checks from Sections 7.2/7.3. These are deterministic circuit interfaces;
// host randomness generation remains outside the relation.
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
// Legacy Kyber: round-three specification v3.02, Section 1.3, Algorithms 7--9.
// https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
// These references define the transforms; the arithmetic optimisations are
// separate local rewrites documented in docs/OPTIMISATIONS.md.
use crate::{pke, sponge};
// Randomness is supplied by the caller; a circuit cannot enforce its entropy.
//
// The scheme is fixed by the name of each public entry point. The shared
// implementations below take a `legacy` selector (false for final FIPS 203
// ML-KEM, true for round-three Kyber) and are private: a caller-supplied,
// possibly witness-valued selector would let a prover switch off the ML-KEM
// decapsulation-key hash check and pick the transform and pk decoding.
// Callers must not branch between these entry points on a witness value.
pub fn mlkem_keygen<let K: u32>(
    d: [u8; 32],
    z: [u8; 32],
) -> ([u8; 384 * K + 32], [u8; 768 * K + 96]) {
    keygen::<K>(d, z, false)
}
pub fn kyber_keygen<let K: u32>(
    d: [u8; 32],
    z: [u8; 32],
) -> ([u8; 384 * K + 32], [u8; 768 * K + 96]) {
    keygen::<K>(d, z, true)
}
pub fn mlkem_encapsulate<let K: u32>(
    pk: [u8; 384 * K + 32],
    entropy: [u8; 32],
) -> ([u8; 320 * K + 128], [u8; 32]) {
    encapsulate::<K>(pk, entropy, false)
}
pub fn kyber_encapsulate<let K: u32>(
    pk: [u8; 384 * K + 32],
    entropy: [u8; 32],
) -> ([u8; 320 * K + 128], [u8; 32]) {
    encapsulate::<K>(pk, entropy, true)
}
pub fn mlkem_decapsulate<let K: u32>(dk: [u8; 768 * K + 96], ct: [u8; 320 * K + 128]) -> [u8; 32] {
    decapsulate::<K>(dk, ct, false)
}
pub fn kyber_decapsulate<let K: u32>(dk: [u8; 768 * K + 96], ct: [u8; 320 * K + 128]) -> [u8; 32] {
    decapsulate::<K>(dk, ct, true)
}
// Seed-form decapsulation: derive the key pair from (d, z), then decapsulate
// with the derived expanded key. The returned pk is a deterministic function of
// d and, by collision resistance of G, determines sk_PKE. A caller that binds
// pk (exact bytes or H(pk)) to a registered key therefore binds the PKE secret
// and the valid-branch key to that recipient. pk does not bind z;
// z selects only the implicit-rejection key, so bind z separately if needed.
pub fn mlkem_decapsulate_from_seeds<let K: u32>(
    d: [u8; 32],
    z: [u8; 32],
    ct: [u8; 320 * K + 128],
) -> ([u8; 384 * K + 32], [u8; 32]) {
    let (pk, dk) = keygen::<K>(d, z, false);
    (pk, decapsulate::<K>(dk, ct, false))
}
pub fn kyber_decapsulate_from_seeds<let K: u32>(
    d: [u8; 32],
    z: [u8; 32],
    ct: [u8; 320 * K + 128],
) -> ([u8; 384 * K + 32], [u8; 32]) {
    let (pk, dk) = keygen::<K>(d, z, true);
    (pk, decapsulate::<K>(dk, ct, true))
}
fn keygen<let K: u32>(
    d: [u8; 32],
    z: [u8; 32],
    legacy: bool,
) -> ([u8; 384 * K + 32], [u8; 768 * K + 96]) {
    // Expanded decapsulation key: sk_PKE || pk || H(pk) || z. The final z
    // is secret fallback material, distinct from the PKE key-generation seed d.
    let (pk, sk) = pke::keygen::<K>(d, legacy);
    let mut dk = [0; 768 * K + 96];
    let h = sponge::h(pk);
    for i in 0..384 * K {
        dk[i] = sk[i];
    }
    for i in 0..384 * K + 32 {
        dk[384 * K + i] = pk[i];
    }
    for i in 0..32 {
        dk[768 * K + 32 + i] = h[i];
        dk[768 * K + 64 + i] = z[i];
    }
    (pk, dk)
}
fn encapsulate<let K: u32>(
    pk: [u8; 384 * K + 32],
    entropy: [u8; 32],
    legacy: bool,
) -> ([u8; 320 * K + 128], [u8; 32]) {
    assert((K == 2) | (K == 3));
    // Kyber Algorithm 8 hashes RNG output and applies KDF(Kbar || H(ct)).
    // ML-KEM Algorithm 17 uses m directly and returns G(m || H(pk))[0..32].
    // Both derive encryption coins from the other half of the same G output.
    let m = if legacy { sponge::h(entropy) } else { entropy };
    // Keep H(pk) in exact SHA3 lanes until G absorbs it; serializing and
    // immediately repacking the digest is unnecessary for the standard relation.
    let hpk = fips202::sponge_lanes::<384 * K + 32, 4, 136, 6>(pk);
    let m_words = sponge::pack_words::<4>(m);
    let mut g_input = [0u64; 8];
    for i in 0..4 {
        g_input[i] = m_words[i];
        g_input[4 + i] = hpk[i];
    }
    let expanded_words = fips202::sponge_words::<8, 8, 72, 6>(g_input);
    let expanded = sponge::unpack_words::<8>(expanded_words);
    let key = sponge::part::<64, 32>(expanded, 0);
    let coins = sponge::part::<64, 32>(expanded, 32);
    // External ML-KEM encapsulation enforces Section 7.2 canonicality.
    // Original Kyber keeps its modular decoder; these domains are intentional.
    let ct = pke::encrypt::<K>(pk, m, coins, !legacy);
    (
        ct,
        if legacy {
            let hct = fips202::sponge_lanes::<320 * K + 128, 4, 136, 6>(ct);
            let mut kdf_input = [0u64; 8];
            for i in 0..4 {
                kdf_input[i] = expanded_words[i];
                kdf_input[4 + i] = hct[i];
            }
            sponge::unpack_words::<4>(fips202::sponge_words::<8, 4, 136, 31>(kdf_input))
        } else {
            key
        },
    )
}
fn decapsulate<let K: u32>(
    dk: [u8; 768 * K + 96],
    ct: [u8; 320 * K + 128],
    legacy: bool,
) -> [u8; 32] {
    assert((K == 2) | (K == 3));
    let sk = sponge::part::<768 * K + 96, 384 * K>(dk, 0);
    let pk = sponge::part::<768 * K + 96, 384 * K + 32>(dk, 384 * K);
    let h = sponge::part::<768 * K + 96, 32>(dk, 768 * K + 32);
    let z = sponge::part::<768 * K + 96, 32>(dk, 768 * K + 64);
    if !legacy {
        assert(sponge::h(pk) == h, "invalid decapsulation-key hash");
    }
    let m = pke::decrypt::<K>(sk, ct);
    let expanded = sponge::g(sponge::join(m, h));
    let key = sponge::part::<64, 32>(expanded, 0);
    let coins = sponge::part::<64, 32>(expanded, 32);
    // Decapsulation checks the stored hash, not encapsulation-key canonicality.
    // FIPS 203 7.3 permits hash-consistent aliases; ByteDecode12 reduces them.
    let check = pke::encrypt::<K>(pk, m, coins, false);
    // Compare every ciphertext byte, then select the required fallback.
    // This must not become assert(check == ct): correctly sized corrupt
    // ciphertexts are valid decapsulation inputs, including the all-zero case.
    // The internal rejection flag is not returned by this API.
    let valid = check == ct;
    if legacy {
        sponge::shake256::<64, 32>(sponge::join(if valid { key } else { z }, sponge::h(ct)))
    } else {
        // ML-KEM Algorithm 18 uses J(z || ct); Kyber above hashes ct first.
        let fallback = sponge::shake256::<32 + 320 * K + 128, 32>(sponge::join(z, ct));
        if valid {
            key
        } else {
            fallback
        }
    }
}
