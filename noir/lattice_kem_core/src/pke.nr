use crate::{poly, sampling, sponge};
pub fn keygen<let K: u32>(d: [u8; 32], legacy: bool) -> ([u8; 384 * K + 32], [u8; 384 * K]) {
    assert((K == 2) | (K == 3));
    let expanded = if legacy {
        sponge::g(d)
    } else {
        sponge::g(sponge::join(d, [K as u8]))
    };
    let rho = sponge::part::<64, 32>(expanded, 0);
    let sigma = sponge::part::<64, 32>(expanded, 32);
    let mut s = [[0u32; 256]; K];
    let mut sk = [0; 384 * K];
    for i in 0..K {
        s[i] = poly::ntt(sampling::noise1::<K>(sigma, i as u8));
        let enc = poly::encode::<12>(s[i]);
        for j in 0..384 {
            sk[i * 384 + j] = enc[j];
        }
    }
    let mut pk = [0; 384 * K + 32];
    for i in 0..K {
        let e = poly::ntt(sampling::noise1::<K>(sigma, (K + i) as u8));
        let mut row = [[0u32; 256]; K];
        for j in 0..K {
            row[j] = sampling::sample_ntt(rho, j as u8, i as u8);
        }
        let t = poly::dot_ntt(row, s, e);
        let enc = poly::encode::<12>(t);
        for j in 0..384 {
            pk[i * 384 + j] = enc[j];
        }
    }
    for i in 0..32 {
        pk[384 * K + i] = rho[i];
    }
    (pk, sk)
}
pub fn encrypt<let K: u32>(
    pk: [u8; 384 * K + 32],
    m: [u8; 32],
    coins: [u8; 32],
    strict: bool,
) -> [u8; 320 * K + 128] {
    let rho = sponge::part::<384 * K + 32, 32>(pk, 384 * K);
    let mut y = [[0u32; 256]; K];
    for i in 0..K {
        y[i] = poly::ntt(sampling::noise1::<K>(coins, i as u8));
    }
    let mut ct = [0; 320 * K + 128];
    let mut t = [[0u32; 256]; K];
    for i in 0..K {
        let mut row = [[0u32; 256]; K];
        for j in 0..K {
            row[j] = sampling::sample_ntt(rho, i as u8, j as u8);
        }
        let uhat = poly::dot_ntt(row, y, [0; 256]);
        let u = poly::inverse_ntt_compress_add::<10>(
            uhat,
            sampling::noise::<2>(coins, (K + i) as u8),
            [0; 256],
        );
        let enc = poly::encode::<10>(u);
        for j in 0..320 {
            ct[320 * i + j] = enc[j];
        }
        t[i] = poly::decode::<12>(sponge::part::<384 * K + 32, 384>(pk, i * 384), strict);
    }
    let mu = poly::decompress::<1>(poly::decode::<1>(m, false));
    let v = poly::inverse_ntt_compress_add::<4>(
        poly::dot_ntt(t, y, [0; 256]),
        sampling::noise::<2>(coins, (2 * K) as u8),
        mu,
    );
    let enc = poly::encode::<4>(v);
    for i in 0..128 {
        ct[320 * K + i] = enc[i];
    }
    ct
}
pub fn decrypt<let K: u32>(sk: [u8; 384 * K], ct: [u8; 320 * K + 128]) -> [u8; 32] {
    let mut s = [[0u32; 256]; K];
    let mut uhat = [[0u32; 256]; K];
    for i in 0..K {
        let u = poly::decompress::<10>(poly::decode::<10>(
            sponge::part::<320 * K + 128, 320>(ct, i * 320),
            false,
        ));
        s[i] = poly::decode::<12>(sponge::part::<384 * K, 384>(sk, i * 384), false);
        uhat[i] = poly::ntt(u);
    }
    let v = poly::decompress::<4>(poly::decode::<4>(
        sponge::part::<320 * K + 128, 128>(ct, 320 * K),
        false,
    ));
    poly::encode::<1>(poly::compress::<1>(poly::sub(
        v,
        poly::inverse_ntt(poly::dot_ntt(s, uhat, [0; 256])),
    )))
}
