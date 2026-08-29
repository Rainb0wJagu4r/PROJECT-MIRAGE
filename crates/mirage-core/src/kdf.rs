use crate::errors::MirageError;
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use sha2::Sha256;
use std::collections::HashSet;
use zeroize::Zeroizing;

pub const PRK_LEN: usize = 32;
pub const SUBKEY_LEN: usize = 32;
pub const KDF_VERSION_LABEL: &str = "mirage/kdf/v2";
pub const MIN_PASSWORD_LENGTH: usize = 12;

pub fn encode_field(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    out
}

pub fn build_kdf_material(
    password: &[u8],
    second_factor: Option<&[u8]>,
    hardware_id: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let mut mat = Vec::new();
    mat.extend_from_slice(&encode_field(KDF_VERSION_LABEL.as_bytes()));
    mat.extend_from_slice(&encode_field(password));
    mat.extend_from_slice(&encode_field(second_factor.unwrap_or(&[])));
    mat.extend_from_slice(&encode_field(hardware_id.unwrap_or(&[])));
    Zeroizing::new(mat)
}

pub fn derive_master_key(
    password: &[u8],
    second_factor: Option<&[u8]>,
    hardware_id: Option<&[u8]>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; PRK_LEN]>, MirageError> {
    if salt.len() < 16 {
        return Err(MirageError::policy(
            "Key Derivation Error: salt inválido (se requieren al menos 16 bytes).",
        ));
    }
    let material = build_kdf_material(password, second_factor, hardware_id);
    
    // Scrypt params: log_n = 17 (N = 131072), r = 8, p = 1
    let params = Params::new(17, 8, 1, 32).map_err(|e| MirageError::policy(e.to_string()))?;
    let mut prk = Zeroizing::new([0u8; PRK_LEN]);
    scrypt(&material, salt, &params, &mut *prk)
        .map_err(|e| MirageError::policy(format!("Scrypt Error: {e}")))?;
    
    Ok(prk)
}

pub fn derive_subkey(
    prk: &[u8; PRK_LEN],
    salt: &[u8],
    label: &str,
) -> Result<Zeroizing<[u8; SUBKEY_LEN]>, MirageError> {
    if !label.starts_with("mirage/") {
        return Err(MirageError::policy(
            "Key Derivation Error: label de subclave inválido.",
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), prk);
    let mut subkey = Zeroizing::new([0u8; SUBKEY_LEN]);
    hk.expand(label.as_bytes(), &mut *subkey)
        .map_err(|_| MirageError::policy("HKDF expansion failed"))?;
    Ok(subkey)
}

pub fn assess_password_strength(password: &str) -> Result<usize, String> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(format!("debe tener al menos {MIN_PASSWORD_LENGTH} caracteres"));
    }
    let mut pool = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }

    let unique: HashSet<char> = password.chars().collect();
    let effective_len = password.len().min(unique.len() * 2);
    let bits = (effective_len as f64 * (pool.max(2) as f64).log2()).floor() as usize;

    if unique.len() < 6 {
        return Err("demasiados caracteres repetidos".to_string());
    }
    if bits < 50 {
        return Err(format!(
            "entropía estimada insuficiente (~{bits} bits); combine mayúsculas, minúsculas, dígitos y símbolos"
        ));
    }
    Ok(bits)
}

pub fn require_password_policy(password: &str, label: &str) -> Result<usize, MirageError> {
    assess_password_strength(password)
        .map_err(|reason| MirageError::policy(format!("Password Policy Error: {label} {reason}.")))
}
