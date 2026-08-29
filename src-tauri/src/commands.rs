use mirage_core::format::{
    append_to_carrier, deserialize_payload, extract_from_carrier, serialize_payload,
};
use mirage_core::kat::{run_known_answer_tests, KatSummary};
use mirage_core::kdf::assess_password_strength;
use mirage_core::paths::safe_basename;
use mirage_core::shamir::{combine_shares, split_secret};
use mirage_core::vault::{
    decrypt_vault, encrypt_vault, Algorithm, DecryptVaultOptions, EncryptVaultOptions,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct FileInfo {
    pub name: String,
    pub size: usize,
    pub hash_sha3: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptRequest {
    pub file_path: String,
    pub password: String,
    pub second_factor: Option<String>,
    pub algorithm: String,
    pub bucket_padding: bool,
    pub split_shamir: bool,
    pub carrier_path: Option<String>,
    pub duress_password: Option<String>,
    pub duress_file_path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptResponse {
    pub success: bool,
    pub output_files: Vec<String>,
    pub elapsed_ms: f64,
    pub original_size: usize,
    pub is_split: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptRequest {
    pub file_paths: Vec<String>,
    pub password: String,
    pub second_factor: Option<String>,
    pub output_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptResponse {
    pub success: bool,
    pub restored_file_path: String,
    pub restored_file_name: String,
    pub restored_size: usize,
    pub is_duress: bool,
    pub elapsed_ms: f64,
}

#[tauri::command]
pub fn pick_file(filter_name: Option<String>, extensions: Option<Vec<String>>) -> Option<String> {
    let mut dialog = rfd::FileDialog::new();
    if let (Some(name), Some(exts)) = (filter_name, extensions) {
        let ext_refs: Vec<&str> = exts.iter().map(|s| s.as_str()).collect();
        dialog = dialog.add_filter(&name, &ext_refs);
    }
    dialog.pick_file().map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
pub fn pick_files() -> Vec<String> {
    rfd::FileDialog::new()
        .pick_files()
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect()
}

#[tauri::command]
pub fn get_file_info(path: String) -> Result<FileInfo, String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err("El archivo no existe.".into());
    }
    let bytes = fs::read(&p).map_err(|e| e.to_string())?;
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    let hash_sha3 = hex::encode(hasher.finalize());

    Ok(FileInfo {
        name: p.file_name().unwrap_or_default().to_string_lossy().to_string(),
        size: bytes.len(),
        hash_sha3,
        path,
    })
}

#[tauri::command]
pub fn assess_password(password: String) -> Result<usize, String> {
    assess_password_strength(&password)
}

#[tauri::command]
pub fn run_kats() -> KatSummary {
    run_known_answer_tests()
}

#[tauri::command]
pub fn encrypt_file_tauri(req: EncryptRequest) -> Result<EncryptResponse, String> {
    let start = std::time::Instant::now();
    let file_path = PathBuf::from(&req.file_path);
    let file_bytes = fs::read(&file_path).map_err(|e| format!("Error al leer archivo: {e}"))?;

    let filename = file_path.file_name().unwrap_or_default().to_string_lossy();
    let payload = serialize_payload(&filename, &file_bytes, 0).map_err(|e| e.public_message())?;

    let mut decoy_payload = None;
    if let (Some(dp_path), Some(_)) = (&req.duress_file_path, &req.duress_password) {
        if let Ok(df_bytes) = fs::read(dp_path) {
            let df_name = Path::new(dp_path).file_name().unwrap_or_default().to_string_lossy();
            decoy_payload = serialize_payload(&df_name, &df_bytes, 0).ok();
        }
    }

    let algo = if req.algorithm.to_lowercase() == "aes-gcm" {
        Algorithm::AesGcm
    } else {
        Algorithm::CascadeC4
    };

    let sf_opt = req.second_factor.as_deref().filter(|s| !s.is_empty());
    let duress_pw_opt = req.duress_password.as_deref().filter(|s| !s.is_empty());

    let enc_res = encrypt_vault(EncryptVaultOptions {
        payload: &payload,
        decoy_payload: decoy_payload.as_deref(),
        password: &req.password,
        second_factor: sf_opt,
        duress_password: duress_pw_opt,
        hardware_id: None,
        algorithm: algo,
        bucket_padding: req.bucket_padding,
        is_vault: false,
    })
    .map_err(|e| e.public_message())?;

    let mut final_data = enc_res.envelope;

    if let Some(c_path) = &req.carrier_path {
        if let Ok(c_bytes) = fs::read(c_path) {
            final_data = append_to_carrier(&c_bytes, &final_data);
        }
    }

    let mut output_files = Vec::new();

    if req.split_shamir {
        let shares = split_secret(&final_data, 2, 3).map_err(|e| e.public_message())?;
        let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
        let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
        for (i, share) in shares.iter().enumerate() {
            let sp = parent.join(format!("{stem}.part{}.share", i + 1));
            fs::write(&sp, share).map_err(|e| format!("Error al escribir fragmento: {e}"))?;
            output_files.push(sp.to_string_lossy().to_string());
        }
    } else {
        let out_path = file_path.with_extension("wraith");
        fs::write(&out_path, &final_data).map_err(|e| format!("Error al escribir .wraith: {e}"))?;
        output_files.push(out_path.to_string_lossy().to_string());
    }

    Ok(EncryptResponse {
        success: true,
        output_files,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        original_size: file_bytes.len(),
        is_split: req.split_shamir,
    })
}

#[tauri::command]
pub fn decrypt_file_tauri(req: DecryptRequest) -> Result<DecryptResponse, String> {
    let start = std::time::Instant::now();
    if req.file_paths.is_empty() {
        return Err("No se proporcionó ningún archivo para descifrar.".into());
    }

    let raw_data = if req.file_paths.len() > 1
        || req.file_paths[0].ends_with(".share")
        || req.file_paths[0].ends_with(".share1")
    {
        let mut share_buffers = Vec::new();
        for f in &req.file_paths {
            let bytes = fs::read(f).map_err(|e| format!("Error al leer {:?}: {e}", f))?;
            share_buffers.push(bytes);
        }
        let slices: Vec<&[u8]> = share_buffers.iter().map(|b| b.as_slice()).collect();
        combine_shares(&slices).map_err(|e| e.public_message())?
    } else {
        fs::read(&req.file_paths[0]).map_err(|e| format!("Error al leer {:?}: {e}", req.file_paths[0]))?
    };

    let (envelope, _was_steg) = extract_from_carrier(&raw_data).unwrap_or((raw_data, false));
    let sf_opt = req.second_factor.as_deref().filter(|s| !s.is_empty());

    let dec = decrypt_vault(
        &envelope,
        DecryptVaultOptions {
            password: &req.password,
            second_factor: sf_opt,
            hardware_id: None,
        },
    )
    .map_err(|e| e.public_message())?;

    let payload = deserialize_payload(&dec.payload).map_err(|e| e.public_message())?;

    let safe_name = safe_basename(&payload.filename, "restored.bin");
    let target_dir = if let Some(od) = &req.output_dir {
        PathBuf::from(od)
    } else {
        Path::new(&req.file_paths[0])
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };

    let target_path = target_dir.join(format!("restored_{safe_name}"));
    fs::write(&target_path, &payload.file_data).map_err(|e| format!("Error al escribir archivo: {e}"))?;

    Ok(DecryptResponse {
        success: true,
        restored_file_path: target_path.to_string_lossy().to_string(),
        restored_file_name: payload.filename,
        restored_size: payload.file_data.len(),
        is_duress: dec.is_duress,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
    })
}

#[tauri::command]
pub fn shamir_split_tauri(file_path: String, threshold: u8, total: u8) -> Result<Vec<String>, String> {
    let p = PathBuf::from(&file_path);
    let bytes = fs::read(&p).map_err(|e| e.to_string())?;
    let shares = split_secret(&bytes, threshold, total).map_err(|e| e.public_message())?;

    let stem = p.file_stem().unwrap_or_default().to_string_lossy();
    let parent = p.parent().unwrap_or_else(|| Path::new("."));
    let mut out_paths = Vec::new();

    for (i, share) in shares.iter().enumerate() {
        let sp = parent.join(format!("{stem}.part{}.share", i + 1));
        fs::write(&sp, share).map_err(|e| e.to_string())?;
        out_paths.push(sp.to_string_lossy().to_string());
    }

    Ok(out_paths)
}
