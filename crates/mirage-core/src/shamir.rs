use crate::errors::MirageError;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const SHARE_MAGIC: &str = "MIRGSHR2";
pub const SHARE_VERSION: u8 = 2;
pub const SHARE_HEADER_LEN: usize = 8 + 1 + 1 + 1 + 1 + 8;
pub const HMAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

// GF(2^8) Tables with irreducible polynomial 0x11B and generator 0x03
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x = 1u8;
        for i in 0..255 {
            exp[i] = x;
            log[x as usize] = i as u8;
            let hi = x & 0x80;
            x = (x << 1) & 0xff;
            if hi != 0 {
                x ^= 0x1b;
            }
            x ^= exp[i];
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let idx = self.log[a as usize] as usize + self.log[b as usize] as usize;
        self.exp[idx]
    }

    fn div(&self, a: u8, b: u8) -> Result<u8, MirageError> {
        if b == 0 {
            return Err(MirageError::opaque("shamir: división por cero en GF(256)"));
        }
        if a == 0 {
            return Ok(0);
        }
        let idx = (self.log[a as usize] as usize + 255 - self.log[b as usize] as usize) % 255;
        Ok(self.exp[idx])
    }
}

fn get_gf() -> Gf256 {
    Gf256::new()
}

fn share_mac_key(secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(b"mirage/shamir/v2/share-mac")
        .expect("HMAC key length valid");
    mac.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn split_secret(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Vec<u8>>, MirageError> {
    if secret.is_empty() {
        return Err(MirageError::policy("Fragment Error: no hay datos que fragmentar."));
    }
    if threshold < 2 || total < threshold {
        return Err(MirageError::policy(
            "Fragment Error: se requiere 2 ≤ umbral ≤ total ≤ 255.",
        ));
    }

    let gf = get_gf();
    let l = secret.len();
    let mut shares = vec![vec![0u8; l]; total as usize];
    let mut rng = rand::thread_rng();
    let mut coeffs = vec![0u8; (threshold - 1) as usize];

    for pos in 0..l {
        rng.fill_bytes(&mut coeffs);
        let a0 = secret[pos];

        for s in 0..total as usize {
            let x = (s + 1) as u8;
            let mut y = 0u8;
            for c in (0..(threshold - 1) as usize).rev() {
                y = gf.mul(y, x) ^ coeffs[c];
            }
            y = gf.mul(y, x) ^ a0;
            shares[s][pos] = y;
        }
    }
    coeffs.zeroize();

    let mut mac_key = share_mac_key(secret);
    let mut out = Vec::with_capacity(total as usize);

    for (idx, share) in shares.iter().enumerate() {
        let mut head = Vec::with_capacity(SHARE_HEADER_LEN);
        head.extend_from_slice(SHARE_MAGIC.as_bytes());
        head.push(SHARE_VERSION);
        head.push((idx + 1) as u8);
        head.push(threshold);
        head.push(total);
        head.extend_from_slice(&(l as u64).to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(&mac_key).unwrap();
        mac.update(&head);
        mac.update(share);
        let tag = mac.finalize().into_bytes();

        let mut packet = Vec::with_capacity(SHARE_HEADER_LEN + HMAC_LEN + l);
        packet.extend_from_slice(&head);
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(share);
        out.push(packet);
    }
    mac_key.zeroize();

    Ok(out)
}

#[derive(Clone, Debug)]
struct ParsedShare<'a> {
    index: u8,
    threshold: u8,
    total: u8,
    secret_len: usize,
    header: &'a [u8],
    mac: &'a [u8],
    share: &'a [u8],
}

fn parse_share(buf: &[u8]) -> Result<ParsedShare, MirageError> {
    if buf.len() < SHARE_HEADER_LEN + HMAC_LEN + 1 {
        return Err(MirageError::opaque("shamir: fragmento demasiado corto"));
    }
    if &buf[0..8] != SHARE_MAGIC.as_bytes() {
        return Err(MirageError::opaque("shamir: magic de fragmento inválido"));
    }
    let version = buf[8];
    if version != SHARE_VERSION {
        return Err(MirageError::opaque(format!(
            "shamir: versión de fragmento no soportada ({version})"
        )));
    }
    let index = buf[9];
    let threshold = buf[10];
    let total = buf[11];
    let secret_len_bytes: [u8; 8] = buf[12..20].try_into().unwrap();
    let secret_len = u64::from_be_bytes(secret_len_bytes) as usize;

    if index < 1 {
        return Err(MirageError::opaque("shamir: índice fuera de rango"));
    }
    if threshold < 2 || total < threshold {
        return Err(MirageError::opaque("shamir: parámetros inconsistentes"));
    }

    let header = &buf[..SHARE_HEADER_LEN];
    let mac = &buf[SHARE_HEADER_LEN..SHARE_HEADER_LEN + HMAC_LEN];
    let share = &buf[SHARE_HEADER_LEN + HMAC_LEN..];

    if share.len() != secret_len {
        return Err(MirageError::opaque(format!(
            "shamir: longitud de fragmento ({}) ≠ declarada ({secret_len})",
            share.len()
        )));
    }

    Ok(ParsedShare {
        index,
        threshold,
        total,
        secret_len,
        header,
        mac,
        share,
    })
}

pub fn combine_shares(share_buffers: &[&[u8]]) -> Result<Vec<u8>, MirageError> {
    if share_buffers.len() < 2 {
        return Err(MirageError::policy(
            "Fragment Error: se requieren al menos 2 fragmentos.",
        ));
    }

    let mut parsed = Vec::with_capacity(share_buffers.len());
    for s in share_buffers {
        parsed.push(parse_share(s)?);
    }

    let threshold = parsed[0].threshold as usize;
    let secret_len = parsed[0].secret_len;

    for p in &parsed {
        if p.threshold as usize != threshold || p.secret_len != secret_len {
            return Err(MirageError::opaque(
                "shamir: los fragmentos no pertenecen al mismo conjunto",
            ));
        }
    }

    if parsed.len() < threshold {
        return Err(MirageError::policy(format!(
            "Fragment Error: se requieren {threshold} fragmentos, se aportaron {}.",
            parsed.len()
        )));
    }

    let mut seen = std::collections::HashSet::new();
    for p in &parsed {
        if !seen.insert(p.index) {
            return Err(MirageError::opaque("shamir: índice de fragmento duplicado"));
        }
    }

    let use_shares = &parsed[..threshold];
    let xs: Vec<u8> = use_shares.iter().map(|p| p.index).collect();
    let mut secret = vec![0u8; secret_len];
    let gf = get_gf();

    for pos in 0..secret_len {
        let mut acc = 0u8;
        for i in 0..use_shares.len() {
            let mut num = 1u8;
            let mut den = 1u8;
            for j in 0..use_shares.len() {
                if i == j {
                    continue;
                }
                num = gf.mul(num, xs[j]);
                den = gf.mul(den, xs[i] ^ xs[j]);
            }
            let term = gf.mul(use_shares[i].share[pos], gf.div(num, den)?);
            acc ^= term;
        }
        secret[pos] = acc;
    }

    let mut mac_key = share_mac_key(&secret);
    for p in use_shares {
        let mut mac = HmacSha256::new_from_slice(&mac_key).unwrap();
        mac.update(p.header);
        mac.update(p.share);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice().ct_eq(p.mac).unwrap_u8() != 1 {
            mac_key.zeroize();
            return Err(MirageError::opaque(format!(
                "shamir: HMAC inválido en el fragmento {}",
                p.index
            )));
        }
    }
    mac_key.zeroize();

    Ok(secret)
}
