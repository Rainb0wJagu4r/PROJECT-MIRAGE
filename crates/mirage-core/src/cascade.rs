use crate::errors::MirageError;
use crate::kdf::{derive_subkey, PRK_LEN};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aria::Aria256;
use camellia::Camellia256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit as CbcKeyIvInit};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::RngCore;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const IV_CAMELLIA_LEN: usize = 16;
pub const NONCE_CHACHA_LEN: usize = 12;
pub const IV_ARIA_LEN: usize = 16;
pub const IV_AES_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub const LABEL_CAMELLIA: &str = "mirage/c4/v2/layer1/camellia-256-cbc";
pub const LABEL_CHACHA: &str = "mirage/c4/v2/layer2/chacha20";
pub const LABEL_ARIA: &str = "mirage/c4/v2/layer3/aria-256-cbc";
pub const LABEL_AES: &str = "mirage/c4/v2/layer4/aes-256-gcm";
pub const LABEL_SINGLE: &str = "mirage/aead/v2/aes-256-gcm";

type CamelliaCbcEnc = cbc::Encryptor<Camellia256>;
type CamelliaCbcDec = cbc::Decryptor<Camellia256>;
type AriaCbcEnc = cbc::Encryptor<Aria256>;
type AriaCbcDec = cbc::Decryptor<Aria256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ivs {
    pub iv_camellia: [u8; IV_CAMELLIA_LEN],
    pub nonce_chacha: [u8; NONCE_CHACHA_LEN],
    pub iv_aria: [u8; IV_ARIA_LEN],
    pub iv_aes: [u8; IV_AES_LEN],
}

impl Ivs {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut iv_camellia = [0u8; IV_CAMELLIA_LEN];
        let mut nonce_chacha = [0u8; NONCE_CHACHA_LEN];
        let mut iv_aria = [0u8; IV_ARIA_LEN];
        let mut iv_aes = [0u8; IV_AES_LEN];

        rng.fill_bytes(&mut iv_camellia);
        rng.fill_bytes(&mut nonce_chacha);
        rng.fill_bytes(&mut iv_aria);
        rng.fill_bytes(&mut iv_aes);

        Self {
            iv_camellia,
            nonce_chacha,
            iv_aria,
            iv_aes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AadContext<'a> {
    pub magic: &'a str,
    pub version: u8,
    pub mode: u8,
    pub flags: u8,
    pub block_index: u8,
    pub block_count: u8,
}

pub fn build_aad(ctx: &AadContext, salt: &[u8], ivs: &Ivs, cipher_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(ctx.magic.as_bytes());
    aad.push(ctx.version);
    aad.push(ctx.mode);
    aad.push(ctx.flags);
    aad.push(ctx.block_index);
    aad.push(ctx.block_count);
    aad.extend_from_slice(&(cipher_len as u64).to_be_bytes());

    aad.extend_from_slice(salt);
    aad.extend_from_slice(&ivs.iv_camellia);
    aad.extend_from_slice(&ivs.nonce_chacha);
    aad.extend_from_slice(&ivs.iv_aria);
    aad.extend_from_slice(&ivs.iv_aes);

    aad
}

pub fn encrypt_cascade(
    plaintext: &[u8],
    prk: &[u8; PRK_LEN],
    salt: &[u8],
    ivs: &Ivs,
    aad_ctx: &AadContext,
) -> Result<(Vec<u8>, [u8; TAG_LEN]), MirageError> {
    let k_cam = derive_subkey(prk, salt, LABEL_CAMELLIA)?;
    let k_cha = derive_subkey(prk, salt, LABEL_CHACHA)?;
    let k_ari = derive_subkey(prk, salt, LABEL_ARIA)?;
    let k_aes = derive_subkey(prk, salt, LABEL_AES)?;

    // Layer 1: Camellia-256-CBC
    let cam_enc = CamelliaCbcEnc::new(k_cam.as_ref().into(), (&ivs.iv_camellia).into());
    let mut s1 = cam_enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Layer 2: ChaCha20
    let mut cha_cipher = ChaCha20::new(k_cha.as_ref().into(), (&ivs.nonce_chacha).into());
    cha_cipher.apply_keystream(&mut s1);
    let mut s2 = s1;

    // Layer 3: ARIA-256-CBC
    let aria_enc = AriaCbcEnc::new(k_ari.as_ref().into(), (&ivs.iv_aria).into());
    let s3 = aria_enc.encrypt_padded_vec_mut::<Pkcs7>(&s2);
    s2.zeroize();

    // Layer 4: AES-256-GCM
    let aad = build_aad(aad_ctx, salt, ivs, s3.len());
    let gcm_cipher = Aes256Gcm::new(k_aes.as_ref().into());
    let gcm_nonce = GcmNonce::from_slice(&ivs.iv_aes);

    let ciphertext_with_tag = gcm_cipher
        .encrypt(
            gcm_nonce,
            Payload {
                msg: &s3,
                aad: &aad,
            },
        )
        .map_err(|e| MirageError::opaque(format!("AES-GCM encrypt error: {e}")))?;

    let split_pos = ciphertext_with_tag.len() - TAG_LEN;
    let ciphertext = ciphertext_with_tag[..split_pos].to_vec();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ciphertext_with_tag[split_pos..]);

    Ok((ciphertext, tag))
}

pub fn decrypt_cascade(
    ciphertext: &[u8],
    prk: &[u8; PRK_LEN],
    salt: &[u8],
    ivs: &Ivs,
    tag: &[u8; TAG_LEN],
    aad_ctx: &AadContext,
) -> Result<Vec<u8>, MirageError> {
    let k_cam = derive_subkey(prk, salt, LABEL_CAMELLIA)?;
    let k_cha = derive_subkey(prk, salt, LABEL_CHACHA)?;
    let k_ari = derive_subkey(prk, salt, LABEL_ARIA)?;
    let k_aes = derive_subkey(prk, salt, LABEL_AES)?;

    let aad = build_aad(aad_ctx, salt, ivs, ciphertext.len());

    // Layer 4: AES-256-GCM
    let gcm_cipher = Aes256Gcm::new(k_aes.as_ref().into());
    let gcm_nonce = GcmNonce::from_slice(&ivs.iv_aes);

    let mut cipher_and_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    cipher_and_tag.extend_from_slice(ciphertext);
    cipher_and_tag.extend_from_slice(tag);

    let s3 = gcm_cipher
        .decrypt(
            gcm_nonce,
            Payload {
                msg: &cipher_and_tag,
                aad: &aad,
            },
        )
        .map_err(|e| MirageError::opaque(format!("cascade v2: fallo de descifrado/autenticación ({e})")))?;

    // Layer 3: ARIA-256-CBC
    let aria_dec = AriaCbcDec::new(k_ari.as_ref().into(), (&ivs.iv_aria).into());
    let mut s2 = aria_dec
        .decrypt_padded_vec_mut::<Pkcs7>(&s3)
        .map_err(|e| MirageError::opaque(format!("cascade v2: fallo en ARIA-CBC ({e})")))?;

    // Layer 2: ChaCha20
    let mut cha_cipher = ChaCha20::new(k_cha.as_ref().into(), (&ivs.nonce_chacha).into());
    cha_cipher.apply_keystream(&mut s2);

    // Layer 1: Camellia-256-CBC
    let cam_dec = CamelliaCbcDec::new(k_cam.as_ref().into(), (&ivs.iv_camellia).into());
    let plaintext = cam_dec
        .decrypt_padded_vec_mut::<Pkcs7>(&s2)
        .map_err(|e| MirageError::opaque(format!("cascade v2: fallo en Camellia-CBC ({e})")))?;

    s2.zeroize();
    Ok(plaintext)
}

pub fn encrypt_single(
    plaintext: &[u8],
    prk: &[u8; PRK_LEN],
    salt: &[u8],
    ivs: &Ivs,
    aad_ctx: &AadContext,
) -> Result<(Vec<u8>, [u8; TAG_LEN]), MirageError> {
    let key = derive_subkey(prk, salt, LABEL_SINGLE)?;
    let aad = build_aad(aad_ctx, salt, ivs, plaintext.len());

    let gcm_cipher = Aes256Gcm::new(key.as_ref().into());
    let gcm_nonce = GcmNonce::from_slice(&ivs.iv_aes);

    let ciphertext_with_tag = gcm_cipher
        .encrypt(
            gcm_nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| MirageError::opaque(format!("AES-GCM single encrypt error: {e}")))?;

    let split_pos = ciphertext_with_tag.len() - TAG_LEN;
    let ciphertext = ciphertext_with_tag[..split_pos].to_vec();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ciphertext_with_tag[split_pos..]);

    Ok((ciphertext, tag))
}

pub fn decrypt_single(
    ciphertext: &[u8],
    prk: &[u8; PRK_LEN],
    salt: &[u8],
    ivs: &Ivs,
    tag: &[u8; TAG_LEN],
    aad_ctx: &AadContext,
) -> Result<Vec<u8>, MirageError> {
    let key = derive_subkey(prk, salt, LABEL_SINGLE)?;
    let aad = build_aad(aad_ctx, salt, ivs, ciphertext.len());

    let gcm_cipher = Aes256Gcm::new(key.as_ref().into());
    let gcm_nonce = GcmNonce::from_slice(&ivs.iv_aes);

    let mut cipher_and_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    cipher_and_tag.extend_from_slice(ciphertext);
    cipher_and_tag.extend_from_slice(tag);

    gcm_cipher
        .decrypt(
            gcm_nonce,
            Payload {
                msg: &cipher_and_tag,
                aad: &aad,
            },
        )
        .map_err(|e| MirageError::opaque(format!("aead v2: fallo de descifrado/autenticación ({e})")))
}
