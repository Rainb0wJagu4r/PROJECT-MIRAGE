use mirage_core::cascade::{
    decrypt_cascade, encrypt_cascade, AadContext, Ivs,
};
use mirage_core::format::{
    deserialize_payload, serialize_payload,
};
use mirage_core::kat::run_known_answer_tests;
use mirage_core::kdf::{
    build_kdf_material, derive_master_key,
};
use mirage_core::padding::{apply_bucket_padding, padme_length, strip_bucket_padding};
use mirage_core::paths::{safe_basename, validate_rel_path};
use mirage_core::shamir::{combine_shares, split_secret};
use mirage_core::vault::{
    decrypt_vault, encrypt_vault, Algorithm, DecryptVaultOptions, EncryptVaultOptions,
};

#[test]
fn test_kat_vectors() {
    let kat = run_known_answer_tests();
    for t in &kat.tests {
        assert!(t.passed, "KAT test '{}' failed: {:?}", t.name, t.detail);
    }
    assert!(kat.overall, "Overall KAT suite must pass 100%");
}

// ---------------------------------------------------------------------------
// MIRAGE-002 — La cascada ya NO es lineal
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_002_non_linear_cascade() {
    let pw = "MasterPassword123!#";
    let salt = [0x42u8; 16];
    let prk = derive_master_key(pw.as_bytes(), None, None, &salt).unwrap();
    let ivs = Ivs::random();

    let p1 = vec![0xaa; 64];
    let p2 = vec![0x55; 64];

    let aad_ctx = AadContext {
        magic: "MIRG",
        version: 2,
        mode: 0x11,
        flags: 0,
        block_index: 0,
        block_count: 1,
    };

    let (c1, tag1) = encrypt_cascade(&p1, &prk, &salt, &ivs, &aad_ctx).unwrap();
    let (c2, _) = encrypt_cascade(&p2, &prk, &salt, &ivs, &aad_ctx).unwrap();

    // 002.1 C1 ^ C2 != P1 ^ P2
    let mut c_xor = vec![0u8; c1.len()];
    for i in 0..c1.len() {
        c_xor[i] = c1[i] ^ c2[i];
    }
    let mut p_xor = vec![0u8; p1.len()];
    for i in 0..p1.len() {
        p_xor[i] = p1[i] ^ p2[i];
    }
    assert_ne!(
        &c_xor[..p_xor.len()],
        p_xor.as_slice(),
        "002.1: La cascada no colapsa en un XOR lineal"
    );

    // 002.4 Ida y vuelta exacta
    let dec = decrypt_cascade(&c1, &prk, &salt, &ivs, &tag1, &aad_ctx).unwrap();
    assert_eq!(dec, p1, "002.4: Descifrado exacto de cascada");

    // 002.3 Difusión: 1 bit cambia ~50%
    let mut p_diff = p1.clone();
    p_diff[0] ^= 0x01;
    let (c_diff, _) = encrypt_cascade(&p_diff, &prk, &salt, &ivs, &aad_ctx).unwrap();
    let mut bit_flips = 0;
    for i in 0..c1.len().min(c_diff.len()) {
        bit_flips += (c1[i] ^ c_diff[i]).count_ones();
    }
    let total_bits = (c1.len() * 8) as f64;
    let ratio = (bit_flips as f64) / total_bits;
    assert!(
        ratio > 0.40 && ratio < 0.60,
        "002.3: Difusión estricta: ratio {ratio:.2} ~ 0.50"
    );
}

// ---------------------------------------------------------------------------
// MIRAGE-005 — Context-Bound AAD
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_005_context_bound_aad() {
    let pw = "MasterPassword123!#";
    let salt = [0x11u8; 16];
    let prk = derive_master_key(pw.as_bytes(), None, None, &salt).unwrap();
    let ivs = Ivs::random();
    let plaintext = b"Confidential Payload 2026";

    let aad_ctx = AadContext {
        magic: "MIRG",
        version: 2,
        mode: 0x11,
        flags: 0,
        block_index: 0,
        block_count: 1,
    };

    let (ct, tag) = encrypt_cascade(plaintext, &prk, &salt, &ivs, &aad_ctx).unwrap();

    // Alter block_index
    let mut bad_ctx = aad_ctx.clone();
    bad_ctx.block_index = 1;
    assert!(
        decrypt_cascade(&ct, &prk, &salt, &ivs, &tag, &bad_ctx).is_err(),
        "005.1: Alterar block_index invalida el tag"
    );

    // Alter block_count
    let mut bad_ctx = aad_ctx.clone();
    bad_ctx.block_count = 2;
    assert!(
        decrypt_cascade(&ct, &prk, &salt, &ivs, &tag, &bad_ctx).is_err(),
        "005.2: Alterar block_count invalida el tag"
    );

    // Alter flags
    let mut bad_ctx = aad_ctx.clone();
    bad_ctx.flags = 0x01; // hardware lock flag altered
    assert!(
        decrypt_cascade(&ct, &prk, &salt, &ivs, &tag, &bad_ctx).is_err(),
        "005.4: Alterar flags invalida el tag"
    );

    // Alter version
    let mut bad_ctx = aad_ctx.clone();
    bad_ctx.version = 1;
    assert!(
        decrypt_cascade(&ct, &prk, &salt, &ivs, &tag, &bad_ctx).is_err(),
        "005.5: Alterar version invalida el tag"
    );

    // Alter ciphertext
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 0x01;
    assert!(
        decrypt_cascade(&bad_ct, &prk, &salt, &ivs, &tag, &aad_ctx).is_err(),
        "005.6: Modificar ciphertext invalida el tag"
    );
}

// ---------------------------------------------------------------------------
// MIRAGE-001 — Path Traversal Containment
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_001_path_containment() {
    assert!(validate_rel_path("../../../.bashrc").is_err());
    assert!(validate_rel_path("/etc/passwd").is_err());
    assert!(validate_rel_path("C:\\Windows\\System32").is_err());
    assert!(validate_rel_path("con.txt").is_err());
    assert!(validate_rel_path("nul").is_err());
    assert!(validate_rel_path("legit_folder/file.pdf").is_ok());

    assert_eq!(safe_basename("CON", "fallback.bin"), "_CON");
    assert_eq!(safe_basename("folder/sub/secret.docx", "fallback.bin"), "secret.docx");
    assert_eq!(safe_basename("", "fallback.bin"), "fallback.bin");
}

// ---------------------------------------------------------------------------
// MIRAGE-007 — TLV Non-collision
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_007_tlv_kdf() {
    let m1 = build_kdf_material(b"userpass12__SECSEC__second1234", None, None);
    let m2 = build_kdf_material(b"userpass12", Some(b"second1234"), None);
    assert_ne!(
        m1.as_slice(),
        m2.as_slice(),
        "007.1: El bypass de colisión v1 ya no existe en v2"
    );
}

// ---------------------------------------------------------------------------
// MIRAGE-009 — Shamir 2-of-3 Secret Sharing
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_009_shamir_secret_sharing() {
    let secret = b"TOP_SECRET_CONTAINER_DATA_2026_GF256";
    let shares = split_secret(secret, 2, 3).unwrap();
    assert_eq!(shares.len(), 3);

    // Any 2 shares reconstruct
    let s0_s1 = [shares[0].as_slice(), shares[1].as_slice()];
    let s1_s2 = [shares[1].as_slice(), shares[2].as_slice()];
    let s0_s2 = [shares[0].as_slice(), shares[2].as_slice()];

    assert_eq!(combine_shares(&s0_s1).unwrap(), secret);
    assert_eq!(combine_shares(&s1_s2).unwrap(), secret);
    assert_eq!(combine_shares(&s0_s2).unwrap(), secret);

    // Tampered share detected by HMAC
    let mut tampered = shares[0].clone();
    *tampered.last_mut().unwrap() ^= 0xff;
    let bad_shares = [tampered.as_slice(), shares[1].as_slice()];
    assert!(combine_shares(&bad_shares).is_err());
}

// ---------------------------------------------------------------------------
// MIRAGE-011 — Padmé Length Quantization
// ---------------------------------------------------------------------------

#[test]
fn test_mirage_011_padme_padding() {
    assert_eq!(padme_length(100), 4096);
    assert_eq!(padme_length(4096), 4096);
    assert!(padme_length(5000) >= 5000);

    let data = b"Sensitive document bytes";
    let padded = apply_bucket_padding(data, true, 0);
    assert!(padded.len() >= 4096);
    let stripped = strip_bucket_padding(&padded).unwrap();
    assert_eq!(stripped, data);
}

// ---------------------------------------------------------------------------
// End-to-End Vault Encryption and Decryption (Mirage-C4 & AES-GCM)
// ---------------------------------------------------------------------------

#[test]
fn test_vault_e2e_mirage_c4_and_duress() {
    let payload_bytes = serialize_payload("report.txt", b"Strategic Confidential Analysis", 0).unwrap();
    let decoy_bytes = serialize_payload("weather.txt", b"Sunny and 75 degrees", 0).unwrap();

    let pw = "MasterPassword123!#";
    let duress_pw = "DecoyPassword456!#";

    // Encrypt in Duress Mode with Mirage-C4
    let enc = encrypt_vault(EncryptVaultOptions {
        payload: &payload_bytes,
        decoy_payload: Some(&decoy_bytes),
        password: pw,
        second_factor: None,
        duress_password: Some(duress_pw),
        hardware_id: None,
        algorithm: Algorithm::CascadeC4,
        bucket_padding: true,
        is_vault: false,
    })
    .unwrap();

    // Decrypt with Master Password -> Real content
    let dec_real = decrypt_vault(
        &enc.envelope,
        DecryptVaultOptions {
            password: pw,
            second_factor: None,
            hardware_id: None,
        },
    )
    .unwrap();
    assert!(!dec_real.is_duress);
    let parsed_real = deserialize_payload(&dec_real.payload).unwrap();
    assert_eq!(parsed_real.filename, "report.txt");
    assert_eq!(parsed_real.file_data, b"Strategic Confidential Analysis");

    // Decrypt with Duress Password -> Decoy content
    let dec_decoy = decrypt_vault(
        &enc.envelope,
        DecryptVaultOptions {
            password: duress_pw,
            second_factor: None,
            hardware_id: None,
        },
    )
    .unwrap();
    assert!(dec_decoy.is_duress);
    let parsed_decoy = deserialize_payload(&dec_decoy.payload).unwrap();
    assert_eq!(parsed_decoy.filename, "weather.txt");
    assert_eq!(parsed_decoy.file_data, b"Sunny and 75 degrees");
}
