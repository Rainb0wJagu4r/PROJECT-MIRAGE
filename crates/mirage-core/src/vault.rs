use crate::cascade::{
    decrypt_cascade, decrypt_single, encrypt_cascade, encrypt_single, AadContext, Ivs,
};
use crate::errors::MirageError;
use crate::format::{
    build_header, cipher_ids, flags, modes, parse_block, parse_header, serialize_block,
    Header, RawBlock, HEADER_LEN, MAGIC, VERSION,
};
use crate::kdf::{derive_master_key, require_password_policy};
use crate::padding::{apply_bucket_padding, strip_bucket_padding};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    CascadeC4,
    AesGcm,
}

impl Algorithm {
    pub fn cipher_id(&self) -> u8 {
        match self {
            Self::CascadeC4 => cipher_ids::CASCADE_C4_V2,
            Self::AesGcm => cipher_ids::AES_GCM,
        }
    }

    pub fn expansion(&self) -> usize {
        match self {
            Self::CascadeC4 => 32,
            Self::AesGcm => 0,
        }
    }
}

pub struct EncryptVaultOptions<'a> {
    pub payload: &'a [u8],
    pub decoy_payload: Option<&'a [u8]>,
    pub password: &'a str,
    pub second_factor: Option<&'a str>,
    pub duress_password: Option<&'a str>,
    pub hardware_id: Option<&'a str>,
    pub algorithm: Algorithm,
    pub bucket_padding: bool,
    pub is_vault: bool,
}

pub struct EncryptedVault {
    pub envelope: Vec<u8>,
    pub flags: u8,
    pub mode: u8,
}

pub fn encrypt_vault(opts: EncryptVaultOptions) -> Result<EncryptedVault, MirageError> {
    require_password_policy(opts.password, "La contraseña maestra")?;
    if let Some(sf) = opts.second_factor {
        if !sf.is_empty() {
            require_password_policy(sf, "El secreto secundario")?;
        }
    }
    if let Some(dp) = opts.duress_password {
        if opts.decoy_payload.is_some() {
            if dp.is_empty() {
                return Err(MirageError::policy("El modo duress requiere una contraseña señuelo."));
            }
            require_password_policy(dp, "La contraseña señuelo")?;
            if dp == opts.password {
                return Err(MirageError::policy("La contraseña señuelo debe ser distinta de la principal."));
            }
            if let Some(sf) = opts.second_factor {
                if !sf.is_empty() && dp == sf {
                    return Err(MirageError::policy("La contraseña señuelo debe ser distinta del secreto secundario."));
                }
            }
        }
    }

    let cipher_id = opts.algorithm.cipher_id();
    let mode = if opts.decoy_payload.is_some() {
        modes::DURESS
    } else if opts.is_vault {
        modes::VAULT
    } else {
        modes::SINGLE
    };
    let block_count = if opts.decoy_payload.is_some() { 2 } else { 1 };

    let mut flags_byte = 0u8;
    if opts.hardware_id.map_or(false, |h| !h.is_empty()) {
        flags_byte |= flags::HARDWARE_LOCK;
    }
    if opts.second_factor.map_or(false, |s| !s.is_empty()) {
        flags_byte |= flags::SECOND_FACTOR;
    }
    if opts.bucket_padding {
        flags_byte |= flags::BUCKET_PADDING;
    }

    let expansion = opts.algorithm.expansion();
    let mut inputs = vec![apply_bucket_padding(opts.payload, opts.bucket_padding, expansion)];
    if let Some(decoy) = opts.decoy_payload {
        inputs.push(apply_bucket_padding(decoy, opts.bucket_padding, expansion));
    }

    let passwords = vec![
        opts.password,
        opts.duress_password.unwrap_or(""),
    ];
    let factors = vec![
        opts.second_factor.unwrap_or(""),
        "", // Decoy does not use 2FA
    ];

    let header_bytes = build_header(&Header {
        version: VERSION,
        mode,
        flags: flags_byte,
        block_count,
        kdf_id: 1,
        cipher_id,
    })?;

    let mut envelope = Vec::new();
    envelope.extend_from_slice(&header_bytes);

    let mut rng = rand::thread_rng();

    for i in 0..block_count as usize {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let ivs = Ivs::random();

        let sf_opt = if factors[i].is_empty() { None } else { Some(factors[i].as_bytes()) };
        let hw_opt = opts.hardware_id.and_then(|h| if h.is_empty() { None } else { Some(h.as_bytes()) });

        let prk = derive_master_key(passwords[i].as_bytes(), sf_opt, hw_opt, &salt)?;

        let aad_ctx = AadContext {
            magic: MAGIC,
            version: VERSION,
            mode,
            flags: flags_byte,
            block_index: i as u8,
            block_count,
        };

        let (ciphertext, tag) = match opts.algorithm {
            Algorithm::CascadeC4 => encrypt_cascade(&inputs[i], &prk, &salt, &ivs, &aad_ctx)?,
            Algorithm::AesGcm => encrypt_single(&inputs[i], &prk, &salt, &ivs, &aad_ctx)?,
        };

        let block = RawBlock {
            salt,
            ivs,
            tag,
            ciphertext,
        };
        envelope.extend_from_slice(&serialize_block(&block));
    }

    for mut inp in inputs {
        inp.zeroize();
    }

    Ok(EncryptedVault {
        envelope,
        flags: flags_byte,
        mode,
    })
}

pub struct DecryptedVault {
    pub payload: Vec<u8>,
    pub is_duress: bool,
    pub hardware_lock_used: bool,
    pub algorithm: Algorithm,
    pub mode: u8,
    pub expiration_time: u64,
}

pub struct DecryptVaultOptions<'a> {
    pub password: &'a str,
    pub second_factor: Option<&'a str>,
    pub hardware_id: Option<&'a str>,
}

pub fn decrypt_vault(
    envelope: &[u8],
    opts: DecryptVaultOptions,
) -> Result<DecryptedVault, MirageError> {
    let header = parse_header(envelope)?;
    let needs_hw = (header.flags & flags::HARDWARE_LOCK) != 0;
    let uses_2fa = (header.flags & flags::SECOND_FACTOR) != 0;

    if needs_hw && opts.hardware_id.map_or(true, |h| h.is_empty()) {
        return Err(MirageError::policy(
            "Este archivo está vinculado a un equipo concreto (hardware-lock) y no se ha podido obtener el identificador de este equipo.",
        ));
    }
    if uses_2fa && opts.second_factor.map_or(true, |s| s.is_empty()) {
        return Err(MirageError::policy(
            "Este archivo requiere un secreto secundario además de la contraseña.",
        ));
    }

    let mut blocks = Vec::with_capacity(header.block_count as usize);
    let mut offset = HEADER_LEN;
    for _ in 0..header.block_count {
        let (blk, next_o) = parse_block(envelope, offset)?;
        blocks.push(blk);
        offset = next_o;
    }

    let algo = match header.cipher_id {
        cipher_ids::CASCADE_C4_V2 => Algorithm::CascadeC4,
        cipher_ids::AES_GCM => Algorithm::AesGcm,
        _ => return Err(MirageError::opaque("cipher_id desconocido")),
    };

    let effective_hw = if needs_hw { opts.hardware_id } else { None };

    // Try block 0
    let mut is_duress = false;
    let mut decrypted_padded = try_block(
        &blocks[0],
        0,
        opts.password,
        opts.second_factor,
        effective_hw,
        &header,
        algo,
    );

    // Try block 1 if duress
    if decrypted_padded.is_none() && header.block_count == 2 {
        decrypted_padded = try_block(
            &blocks[1],
            1,
            opts.password,
            None, // Decoy has no 2FA
            effective_hw,
            &header,
            algo,
        );
        if decrypted_padded.is_some() {
            is_duress = true;
        }
    }

    let padded = decrypted_padded
        .ok_or_else(|| MirageError::opaque("vault: ningún bloque autenticó con las credenciales dadas"))?;

    let inner = strip_bucket_padding(&padded)?;

    // Peek TTL
    let expiration_time = if inner.len() >= 8 {
        u64::from_be_bytes(inner[0..8].try_into().unwrap())
    } else {
        0
    };

    if expiration_time > 0 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now_ms > expiration_time {
            return Err(MirageError::policy(format!(
                "El archivo declara haber expirado (TTL {} ms).",
                expiration_time
            )));
        }
    }

    Ok(DecryptedVault {
        payload: inner,
        is_duress,
        hardware_lock_used: needs_hw,
        algorithm: algo,
        mode: header.mode,
        expiration_time,
    })
}

fn try_block(
    block: &RawBlock,
    block_index: u8,
    password: &str,
    second_factor: Option<&str>,
    hardware_id: Option<&str>,
    header: &Header,
    algo: Algorithm,
) -> Option<Vec<u8>> {
    let sf_bytes = second_factor.and_then(|s| if s.is_empty() { None } else { Some(s.as_bytes()) });
    let hw_bytes = hardware_id.and_then(|h| if h.is_empty() { None } else { Some(h.as_bytes()) });

    let prk = derive_master_key(password.as_bytes(), sf_bytes, hw_bytes, &block.salt).ok()?;

    let aad_ctx = AadContext {
        magic: MAGIC,
        version: VERSION,
        mode: header.mode,
        flags: header.flags,
        block_index,
        block_count: header.block_count,
    };

    let res = match algo {
        Algorithm::CascadeC4 => decrypt_cascade(
            &block.ciphertext,
            &prk,
            &block.salt,
            &block.ivs,
            &block.tag,
            &aad_ctx,
        ),
        Algorithm::AesGcm => decrypt_single(
            &block.ciphertext,
            &prk,
            &block.salt,
            &block.ivs,
            &block.tag,
            &aad_ctx,
        ),
    };

    res.ok()
}
