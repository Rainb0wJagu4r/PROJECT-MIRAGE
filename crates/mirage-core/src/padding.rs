use crate::errors::MirageError;
use rand::RngCore;

pub const LEN_PREFIX: usize = 8;
pub const MIN_BUCKET: usize = 4096;

pub fn padme_length(l: usize) -> usize {
    if l <= MIN_BUCKET {
        return MIN_BUCKET;
    }
    let l_f64 = l as f64;
    let e = l_f64.log2().floor() as usize;
    let s = (e as f64).log2().floor() as usize + 1;
    let z = if e >= s { e - s } else { 0 };
    let mask = (1usize << z).saturating_sub(1);
    let padded = (l + mask) & !mask;
    padded.max(l)
}

pub fn apply_bucket_padding(buffer: &[u8], enabled: bool, expansion: usize) -> Vec<u8> {
    let real_len = buffer.len();
    let mut out = Vec::with_capacity(real_len + LEN_PREFIX);
    out.extend_from_slice(&(real_len as u64).to_be_bytes());
    out.extend_from_slice(buffer);

    if !enabled {
        return out;
    }

    let final_target = padme_length(real_len + LEN_PREFIX + expansion);
    if final_target > expansion + real_len + LEN_PREFIX {
        let pad_len = final_target - expansion - real_len - LEN_PREFIX;
        let mut filler = vec![0u8; pad_len];
        rand::thread_rng().fill_bytes(&mut filler);
        out.extend_from_slice(&filler);
    }
    out
}

pub fn strip_bucket_padding(padded: &[u8]) -> Result<Vec<u8>, MirageError> {
    if padded.len() < LEN_PREFIX {
        return Err(MirageError::opaque(
            "padding: bloque demasiado corto para contener el prefijo",
        ));
    }
    let real_len_bytes: [u8; 8] = padded[0..8].try_into().unwrap();
    let real_len = u64::from_be_bytes(real_len_bytes) as usize;

    if real_len > padded.len() - LEN_PREFIX {
        return Err(MirageError::opaque(format!(
            "padding: longitud declarada ({real_len}) excede el bloque ({})",
            padded.len() - LEN_PREFIX
        )));
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + real_len].to_vec())
}
