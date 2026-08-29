use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use aria::Aria256;
use camellia::Camellia256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockEncryptMut, KeyIvInit as CbcKeyIvInit};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KatResult {
    pub name: String,
    pub source: String,
    pub passed: bool,
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KatSummary {
    pub overall: bool,
    pub disclaimer: String,
    pub tests: Vec<KatResult>,
}

type CamelliaCbcRaw = cbc::Encryptor<Camellia256>;
type AriaCbcRaw = cbc::Encryptor<Aria256>;

fn hex_bytes(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

pub fn run_known_answer_tests() -> KatSummary {
    let mut tests = Vec::new();

    // 1. AES-256-GCM tag (empty plaintext) - GCM spec Test Case 13
    {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let cipher = Aes256Gcm::new((&key).into());
        let res = cipher.encrypt((&iv).into(), Payload { msg: b"", aad: b"" });
        let expected = hex_bytes("530f8afbc74536b9a963b4f1c4cb738b");
        let (passed, detail) = match res {
            Ok(ct) => {
                if ct == expected {
                    (true, None)
                } else {
                    (false, Some(format!("got {:?}, want {:?}", ct, expected)))
                }
            }
            Err(e) => (false, Some(e.to_string())),
        };
        tests.push(KatResult {
            name: "AES-256-GCM tag (plaintext vacío)".into(),
            source: "GCM spec, Test Case 13".into(),
            passed,
            detail,
        });
    }

    // 2. AES-256-GCM ciphertext - GCM spec Test Case 14
    {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = Aes256Gcm::new((&key).into());
        let res = cipher.encrypt((&iv).into(), Payload { msg: &pt, aad: b"" });
        let expected_ct = hex_bytes("cea7403d4d606b6e074ec5d3baf39d18");
        let expected_tag = hex_bytes("d0d1c8a799996bf0265b98b5d48ab919");
        let mut expected = expected_ct;
        expected.extend_from_slice(&expected_tag);

        let (passed, detail) = match res {
            Ok(ct) => {
                if ct == expected {
                    (true, None)
                } else {
                    (false, Some("ciphertext/tag mismatch".into()))
                }
            }
            Err(e) => (false, Some(e.to_string())),
        };
        tests.push(KatResult {
            name: "AES-256-GCM ciphertext + tag".into(),
            source: "GCM spec, Test Case 14".into(),
            passed,
            detail,
        });
    }

    // 3. ChaCha20 keystream - RFC 8439 §2.4.2
    {
        let key = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_bytes("000000000000004a00000000");

        let mut block = [0u8; 64];
        let mut cipher = ChaCha20::new(key.as_slice().into(), nonce.as_slice().into());
        cipher.seek(64); // counter = 1
        cipher.apply_keystream(&mut block);

        let expected = hex_bytes(
            "224f51f3401bd9e12fde276fb8631ded\
             8c131f823d2c06e27e4fcaec9ef3cf78\
             8a3b0aa372600a92b57974cded2b9334\
             794cba40c63e34cdea212c4cf07d41b7",
        );
        let passed = block.as_slice() == expected.as_slice();
        tests.push(KatResult {
            name: "ChaCha20 keystream".into(),
            source: "RFC 8439 §2.4.2".into(),
            passed,
            detail: if passed { None } else { Some("mismatch".into()) },
        });
    }

    // 4. Camellia-256 (single block) - RFC 3713 / NESSIE
    {
        let key = hex_bytes(
            "0123456789abcdeffedcba9876543210\
             00112233445566778899aabbccddeeff",
        );
        let pt = hex_bytes("0123456789abcdeffedcba9876543210");
        let iv = [0u8; 16];
        let enc = CamelliaCbcRaw::new(key.as_slice().into(), (&iv).into());
        let ct = enc.encrypt_padded_vec_mut::<NoPadding>(&pt);
        let expected = hex_bytes("9acc237dff16d76c20ef7c919e3a7509");
        let passed = ct == expected;
        tests.push(KatResult {
            name: "Camellia-256 (bloque único)".into(),
            source: "RFC 3713 / NESSIE".into(),
            passed,
            detail: if passed { None } else { Some("mismatch".into()) },
        });
    }

    // 5. ARIA-256 (single block) - RFC 5794 §A.3
    {
        let key = hex_bytes(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
        );
        let pt = hex_bytes("00112233445566778899aabbccddeeff");
        let iv = [0u8; 16];
        let enc = AriaCbcRaw::new(key.as_slice().into(), (&iv).into());
        let ct = enc.encrypt_padded_vec_mut::<NoPadding>(&pt);
        let expected = hex_bytes("f92bd7c79fb72e2f2b8f80c1972d24fc");
        let passed = ct == expected;
        tests.push(KatResult {
            name: "ARIA-256 (bloque único)".into(),
            source: "RFC 5794 §A.3".into(),
            passed,
            detail: if passed { None } else { Some("mismatch".into()) },
        });
    }

    // 6. HKDF-SHA256 - RFC 5869 Test Case 1
    {
        let ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_bytes("000102030405060708090a0b0c");
        let info = hex_bytes("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        let res = hk.expand(&info, &mut okm);
        let expected = hex_bytes(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let passed = res.is_ok() && okm.as_slice() == expected.as_slice();
        tests.push(KatResult {
            name: "HKDF-SHA256".into(),
            source: "RFC 5869 Test Case 1".into(),
            passed,
            detail: if passed { None } else { Some("mismatch".into()) },
        });
    }

    // 7. Scrypt - RFC 7914 §12 (N=16, r=1, p=1)
    {
        let mut out = [0u8; 64];
        let params = Params::new(4, 1, 1, 64).unwrap(); // 2^4 = 16
        let res = scrypt(b"", b"", &params, &mut out);
        let expected = hex_bytes(
            "77d6576238657b203b19ca42c18a0497\
             f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17\
             e8d3e0fb2e0d3628cf35e20c38d18906",
        );
        let passed = res.is_ok() && out.as_slice() == expected.as_slice();
        tests.push(KatResult {
            name: "scrypt".into(),
            source: "RFC 7914 §12 (N=16, r=1, p=1)".into(),
            passed,
            detail: if passed { None } else { Some("mismatch".into()) },
        });
    }

    let overall = tests.iter().all(|t| t.passed);
    KatSummary {
        overall,
        disclaimer: "Los KAT comprueban que las primitivas coinciden con vectores publicados. \
                     NO evalúan el diseño del protocolo ni demuestran que la aplicación sea segura."
            .into(),
        tests,
    }
}
