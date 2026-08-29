use crate::cascade::{Ivs, IV_AES_LEN, IV_ARIA_LEN, IV_CAMELLIA_LEN, NONCE_CHACHA_LEN, SALT_LEN, TAG_LEN};
use crate::errors::MirageError;

pub const MAGIC: &str = "MIRG";
pub const VERSION: u8 = 2;

pub mod modes {
    pub const SINGLE: u8 = 0x11;
    pub const DURESS: u8 = 0x12;
    pub const VAULT: u8 = 0x13;
}

pub mod flags {
    pub const HARDWARE_LOCK: u8 = 0x01;
    pub const SECOND_FACTOR: u8 = 0x02;
    pub const BUCKET_PADDING: u8 = 0x04;
}

pub mod cipher_ids {
    pub const CASCADE_C4_V2: u8 = 1;
    pub const AES_GCM: u8 = 2;
}

pub mod kdf_ids {
    pub const SCRYPT_HKDF_V2: u8 = 1;
}

pub const HEADER_LEN: usize = 12;
pub const LEN_FIELD: usize = 8;
pub const BLOCK_META_LEN: usize =
    SALT_LEN + IV_CAMELLIA_LEN + NONCE_CHACHA_LEN + IV_ARIA_LEN + IV_AES_LEN + TAG_LEN + LEN_FIELD; // 96
pub const MAX_CIPHER_LEN: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_FILENAME_LEN: usize = 4096;

pub const STEG_MAGIC: &str = "MIRGSTG2";
pub const STEG_TRAILER_LEN: usize = 8 + 8;

pub const VAULT_MAGIC: &str = "MIRG_VLT2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub mode: u8,
    pub flags: u8,
    pub block_count: u8,
    pub kdf_id: u8,
    pub cipher_id: u8,
}

pub fn build_header(h: &Header) -> Result<[u8; HEADER_LEN], MirageError> {
    if h.mode != modes::SINGLE && h.mode != modes::DURESS && h.mode != modes::VAULT {
        return Err(MirageError::opaque(format!("format: modo inválido (0x{:x})", h.mode)));
    }
    if h.block_count != 1 && h.block_count != 2 {
        return Err(MirageError::opaque(format!("format: blockCount inválido ({})", h.block_count)));
    }
    if h.cipher_id != cipher_ids::CASCADE_C4_V2 && h.cipher_id != cipher_ids::AES_GCM {
        return Err(MirageError::opaque(format!("format: cipherId inválido ({})", h.cipher_id)));
    }

    let mut out = [0u8; HEADER_LEN];
    out[0..4].copy_from_slice(MAGIC.as_bytes());
    out[4] = VERSION;
    out[5] = h.mode;
    out[6] = h.flags;
    out[7] = h.block_count;
    out[8] = h.kdf_id;
    out[9] = h.cipher_id;
    out[10] = 0;
    out[11] = 0;
    Ok(out)
}

pub fn parse_header(buf: &[u8]) -> Result<Header, MirageError> {
    if buf.len() < HEADER_LEN {
        return Err(MirageError::opaque("format: archivo demasiado corto para la cabecera"));
    }
    if &buf[0..4] != MAGIC.as_bytes() {
        return Err(MirageError::opaque("format: magic incorrecto"));
    }
    let version = buf[4];
    if version != VERSION {
        return Err(MirageError::opaque(format!(
            "format: versión no soportada ({version})"
        )));
    }
    let mode = buf[5];
    if mode != modes::SINGLE && mode != modes::DURESS && mode != modes::VAULT {
        return Err(MirageError::opaque(format!("format: modo no reconocido (0x{mode:x})")));
    }
    let flags = buf[6];
    let block_count = buf[7];
    if block_count != 1 && block_count != 2 {
        return Err(MirageError::opaque(format!("format: blockCount inválido ({block_count})")));
    }
    let kdf_id = buf[8];
    if kdf_id != kdf_ids::SCRYPT_HKDF_V2 {
        return Err(MirageError::opaque(format!("format: kdfId no soportado ({kdf_id})")));
    }
    let cipher_id = buf[9];
    if cipher_id != cipher_ids::CASCADE_C4_V2 && cipher_id != cipher_ids::AES_GCM {
        return Err(MirageError::opaque(format!("format: cipherId no soportado ({cipher_id})")));
    }

    Ok(Header {
        version,
        mode,
        flags,
        block_count,
        kdf_id,
        cipher_id,
    })
}

#[derive(Clone, Debug)]
pub struct RawBlock {
    pub salt: [u8; SALT_LEN],
    pub ivs: Ivs,
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn serialize_block(block: &RawBlock) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLOCK_META_LEN + block.ciphertext.len());
    out.extend_from_slice(&block.salt);
    out.extend_from_slice(&block.ivs.iv_camellia);
    out.extend_from_slice(&block.ivs.nonce_chacha);
    out.extend_from_slice(&block.ivs.iv_aria);
    out.extend_from_slice(&block.ivs.iv_aes);
    out.extend_from_slice(&block.tag);
    out.extend_from_slice(&(block.ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(&block.ciphertext);
    out
}

pub fn parse_block(buffer: &[u8], offset: usize) -> Result<(RawBlock, usize), MirageError> {
    if offset + BLOCK_META_LEN > buffer.len() {
        return Err(MirageError::opaque("format: faltan bytes para metainformación de bloque"));
    }

    let mut o = offset;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buffer[o..o + SALT_LEN]);
    o += SALT_LEN;

    let mut iv_camellia = [0u8; IV_CAMELLIA_LEN];
    iv_camellia.copy_from_slice(&buffer[o..o + IV_CAMELLIA_LEN]);
    o += IV_CAMELLIA_LEN;

    let mut nonce_chacha = [0u8; NONCE_CHACHA_LEN];
    nonce_chacha.copy_from_slice(&buffer[o..o + NONCE_CHACHA_LEN]);
    o += NONCE_CHACHA_LEN;

    let mut iv_aria = [0u8; IV_ARIA_LEN];
    iv_aria.copy_from_slice(&buffer[o..o + IV_ARIA_LEN]);
    o += IV_ARIA_LEN;

    let mut iv_aes = [0u8; IV_AES_LEN];
    iv_aes.copy_from_slice(&buffer[o..o + IV_AES_LEN]);
    o += IV_AES_LEN;

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buffer[o..o + TAG_LEN]);
    o += TAG_LEN;

    let cipher_len_bytes: [u8; 8] = buffer[o..o + LEN_FIELD].try_into().unwrap();
    let cipher_len = u64::from_be_bytes(cipher_len_bytes);
    o += LEN_FIELD;

    if cipher_len > MAX_CIPHER_LEN {
        return Err(MirageError::opaque("format: cipherLen supera el máximo"));
    }
    let cipher_len_usize = cipher_len as usize;
    if o + cipher_len_usize > buffer.len() {
        return Err(MirageError::opaque("format: bloque truncado"));
    }

    let ciphertext = buffer[o..o + cipher_len_usize].to_vec();
    o += cipher_len_usize;

    Ok((
        RawBlock {
            salt,
            ivs: Ivs {
                iv_camellia,
                nonce_chacha,
                iv_aria,
                iv_aes,
            },
            tag,
            ciphertext,
        },
        o,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedPayload {
    pub expiration_time: u64,
    pub filename: String,
    pub file_data: Vec<u8>,
}

pub fn serialize_payload(
    filename: &str,
    file_buffer: &[u8],
    expiration_time: u64,
) -> Result<Vec<u8>, MirageError> {
    let name_bytes = filename.as_bytes();
    if name_bytes.is_empty() {
        return Err(MirageError::opaque("format: nombre de archivo vacío"));
    }
    if name_bytes.len() > MAX_FILENAME_LEN {
        return Err(MirageError::opaque("format: nombre de archivo demasiado largo"));
    }

    let mut out = Vec::with_capacity(8 + 2 + name_bytes.len() + 8 + file_buffer.len());
    out.extend_from_slice(&expiration_time.to_be_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&(file_buffer.len() as u64).to_be_bytes());
    out.extend_from_slice(file_buffer);
    Ok(out)
}

pub fn deserialize_payload(buffer: &[u8]) -> Result<DecryptedPayload, MirageError> {
    if buffer.len() < 18 {
        return Err(MirageError::opaque("format: payload demasiado corto"));
    }
    let exp_bytes: [u8; 8] = buffer[0..8].try_into().unwrap();
    let expiration_time = u64::from_be_bytes(exp_bytes);

    let name_len_bytes: [u8; 2] = buffer[8..10].try_into().unwrap();
    let name_len = u16::from_be_bytes(name_len_bytes) as usize;

    if name_len == 0 || name_len > MAX_FILENAME_LEN || 10 + name_len + 8 > buffer.len() {
        return Err(MirageError::opaque("format: nombre inválido en payload"));
    }

    let name_bytes = &buffer[10..10 + name_len];
    if name_bytes.contains(&0x00) {
        return Err(MirageError::opaque("format: el nombre contiene byte NUL"));
    }
    let filename = String::from_utf8(name_bytes.to_vec())
        .map_err(|_| MirageError::opaque("format: nombre no es UTF-8 válido"))?;

    let size_offset = 10 + name_len;
    let data_start = size_offset + 8;
    let size_bytes: [u8; 8] = buffer[size_offset..data_start].try_into().unwrap();
    let file_size = u64::from_be_bytes(size_bytes) as usize;

    if data_start + file_size > buffer.len() {
        return Err(MirageError::opaque("format: tamaño de archivo excede payload"));
    }

    let file_data = buffer[data_start..data_start + file_size].to_vec();

    Ok(DecryptedPayload {
        expiration_time,
        filename,
        file_data,
    })
}

pub fn append_to_carrier(carrier: &[u8], envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(carrier.len() + envelope.len() + STEG_TRAILER_LEN);
    out.extend_from_slice(carrier);
    out.extend_from_slice(envelope);
    out.extend_from_slice(&(envelope.len() as u64).to_be_bytes());
    out.extend_from_slice(STEG_MAGIC.as_bytes());
    out
}

pub fn extract_from_carrier(buffer: &[u8]) -> Result<(Vec<u8>, bool), MirageError> {
    if buffer.len() < STEG_TRAILER_LEN || &buffer[buffer.len() - 8..] != STEG_MAGIC.as_bytes() {
        return Ok((buffer.to_vec(), false));
    }
    let available = buffer.len() - STEG_TRAILER_LEN;
    let len_bytes: [u8; 8] = buffer[available..available + 8].try_into().unwrap();
    let payload_len = u64::from_be_bytes(len_bytes) as usize;

    if payload_len == 0 || payload_len > available {
        return Err(MirageError::opaque("steg: payloadLen inválido"));
    }

    let start = available - payload_len;
    Ok((buffer[start..available].to_vec(), true))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultEntry {
    pub rel_path: String,
    pub content: Vec<u8>,
}

pub fn serialize_multi_payload(
    files: &[VaultEntry],
    expiration_time: u64,
) -> Result<Vec<u8>, MirageError> {
    let mut out = Vec::new();
    out.extend_from_slice(VAULT_MAGIC.as_bytes());
    out.extend_from_slice(&expiration_time.to_be_bytes());
    out.extend_from_slice(&(files.len() as u32).to_be_bytes());

    for f in files {
        let rel_bytes = f.rel_path.as_bytes();
        if rel_bytes.is_empty() || rel_bytes.len() > MAX_FILENAME_LEN {
            return Err(MirageError::opaque("format: relPath inválido"));
        }
        out.extend_from_slice(&(rel_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(rel_bytes);
        out.extend_from_slice(&(f.content.len() as u64).to_be_bytes());
        out.extend_from_slice(&f.content);
    }
    Ok(out)
}

pub fn deserialize_multi_payload(
    buffer: &[u8],
) -> Result<(Vec<VaultEntry>, u64), MirageError> {
    let min_head = VAULT_MAGIC.len() + 8 + 4;
    if buffer.len() < min_head || &buffer[0..VAULT_MAGIC.len()] != VAULT_MAGIC.as_bytes() {
        return Err(MirageError::opaque("format: magic de bóveda incorrecto"));
    }
    let mut o = VAULT_MAGIC.len();
    let exp_bytes: [u8; 8] = buffer[o..o + 8].try_into().unwrap();
    let expiration_time = u64::from_be_bytes(exp_bytes);
    o += 8;

    let count_bytes: [u8; 4] = buffer[o..o + 4].try_into().unwrap();
    let count = u32::from_be_bytes(count_bytes) as usize;
    o += 4;

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if o + 2 > buffer.len() {
            return Err(MirageError::opaque("format: bóveda truncada"));
        }
        let rel_len = u16::from_be_bytes(buffer[o..o + 2].try_into().unwrap()) as usize;
        o += 2;
        if rel_len == 0 || rel_len > MAX_FILENAME_LEN || o + rel_len + 8 > buffer.len() {
            return Err(MirageError::opaque("format: longitud de entrada en bóveda inválida"));
        }
        let rel_path = String::from_utf8(buffer[o..o + rel_len].to_vec())
            .map_err(|_| MirageError::opaque("format: ruta no es UTF-8"))?;
        o += rel_len;

        let size = u64::from_be_bytes(buffer[o..o + 8].try_into().unwrap()) as usize;
        o += 8;
        if o + size > buffer.len() {
            return Err(MirageError::opaque("format: contenido de archivo en bóveda truncado"));
        }
        let content = buffer[o..o + size].to_vec();
        o += size;
        entries.push(VaultEntry { rel_path, content });
    }

    Ok((entries, expiration_time))
}
