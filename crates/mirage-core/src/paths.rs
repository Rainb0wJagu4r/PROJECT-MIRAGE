use crate::errors::MirageError;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

const MAX_REL_PATH_LENGTH: usize = 1024;

pub fn validate_rel_path(rel: &str) -> Result<(), String> {
    if rel.is_empty() {
        return Err("ruta vacía o no es string".to_string());
    }
    if rel.len() > MAX_REL_PATH_LENGTH {
        return Err(format!("ruta demasiado larga ({})", rel.len()));
    }
    if rel.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f) {
        return Err("contiene bytes NUL o de control".to_string());
    }
    if rel.starts_with('/') {
        return Err("ruta absoluta POSIX".to_string());
    }
    if rel.len() >= 2 && rel.chars().next().unwrap().is_ascii_alphabetic() && rel.chars().nth(1).unwrap() == ':' {
        return Err("ruta absoluta Windows con letra de unidad".to_string());
    }
    if rel.starts_with("\\\\") || rel.starts_with("//") {
        return Err("ruta UNC o namespace Win32".to_string());
    }

    let parts: Vec<&str> = rel.split(['/', '\\']).collect();
    if parts.iter().any(|p| *p == "..") {
        return Err("contiene componente de traversal \"..\"".to_string());
    }

    let reserved: HashSet<&str> = WINDOWS_RESERVED.iter().copied().collect();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let base = p.split('.').next().unwrap_or("").to_lowercase();
        let base_trimmed = base.trim();
        if reserved.contains(base_trimmed) {
            return Err(format!("nombre reservado de Windows: {p}"));
        }
    }

    Ok(())
}

pub fn safe_join(base: &Path, rel: &str) -> Result<PathBuf, MirageError> {
    if let Err(reason) = validate_rel_path(rel) {
        return Err(MirageError::opaque(format!(
            "safeJoin rechazó la ruta: {reason} ({rel:?})"
        )));
    }

    let base_canonical = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    
    // Sanitize relative path
    let mut normalized = PathBuf::new();
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(MirageError::opaque(
                    "safeJoin: componente hostil en ruta relativa",
                ));
            }
        }
    }

    let target = base_canonical.join(normalized);
    
    // Verify target starts with base_canonical
    if !target.starts_with(&base_canonical) {
        return Err(MirageError::opaque(format!(
            "safeJoin: la ruta escapa del directorio destino ({target:?})"
        )));
    }
    if target == base_canonical {
        return Err(MirageError::opaque(
            "safeJoin: la ruta resuelve al propio directorio destino",
        ));
    }

    Ok(target)
}

pub fn safe_basename(name: &str, fallback: &str) -> String {
    if name.is_empty() {
        return fallback.to_string();
    }
    let cut = name.split('\0').next().unwrap_or("");
    let base = cut.split(['/', '\\']).filter(|s| !s.is_empty()).last().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| (*c as u32) >= 0x20 && (*c as u32) != 0x7f)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return fallback.to_string();
    }

    let reserved: HashSet<&str> = WINDOWS_RESERVED.iter().copied().collect();
    let base_no_ext = cleaned.split('.').next().unwrap_or("").to_lowercase();
    if reserved.contains(base_no_ext.as_str()) {
        return format!("_{cleaned}");
    }
    if cleaned.len() > 255 {
        return cleaned[cleaned.len() - 255..].to_string();
    }
    cleaned.to_string()
}

pub fn require_user_path(p: &str, label: &str) -> Result<PathBuf, MirageError> {
    if p.trim().is_empty() {
        return Err(MirageError::policy(format!(
            "Path Error: se requiere {label}."
        )));
    }
    if p.contains('\0') {
        return Err(MirageError::policy(format!(
            "Path Error: {label} contiene bytes inválidos."
        )));
    }
    let trimmed = p.trim();
    if trimmed.starts_with('~') {
        if let Some(home) = std::env::var_os("HOME") {
            let mut buf = PathBuf::from(home);
            buf.push(&trimmed[1..].trim_start_matches(['/', '\\']));
            return Ok(buf);
        }
    }
    Ok(PathBuf::from(trimmed))
}
