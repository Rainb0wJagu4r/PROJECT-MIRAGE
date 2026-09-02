<p align="center">
  <img src="assets/wraith_icon.png" width="128" height="128" alt="Project Mirage Logo" />
</p>

<h1 align="center">Project Mirage</h1>
<p align="center">
  <strong>Armored Symmetric Cryptosystem (Mirage-C4 v2) & Native Desktop Vault in Rust</strong>
</p>

<p align="center">
  <a href="https://fileinfo.com/extension/wraith"><img src="https://img.shields.io/badge/FileInfo.com-.WRAITH_Registered-8A2BE2?style=for-the-badge&logo=checkmarx&logoColor=white" alt="FileInfo.com Verified" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.80%2B-orange?style=for-the-badge&logo=rust" alt="Rust 1.80+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" /></a>
  <a href="crates/mirage-core/tests/security_tests.rs"><img src="https://img.shields.io/badge/KAT_Tests-100%25_PASS-brightgreen?style=for-the-badge" alt="KAT Tests 100% PASS" /></a>
</p>

---

> 🏆 **Official .WRAITH File Extension Recognition**  
> The **`.wraith`** format (Project Mirage Encrypted Archive) is officially recognized and indexed in the global file format directory:  
> 👉 **[https://fileinfo.com/extension/wraith](https://fileinfo.com/extension/wraith)**

> [!NOTE]
> **Legacy JavaScript Stack Retired & Purged**  
> All legacy Node.js, Express, and Electron dependencies have been completely retired and purged from the repository. Project Mirage is now a **100% native Rust project**, eliminating JavaScript supply chain attack vectors, runtime memory persistence vulnerabilities, and third-party npm package overhead.

> [!WARNING]
> **Project Origin & Active Development Status**
> - 🇲🇽 **Born in Mexico:** This project is proud to be born in Mexico.
> - **Active Development:** The software is actively developed and maintained as an open-source armored cryptosystem.
> - **Statistical tests (NIST SP 800-22):** The output of `.wraith` archives passes the SP 800-22 suite: [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).
> - **Key Zeroization in RAM:** Master keys and derived subkeys implement the `Zeroize` trait, wiping sensitive cryptographic material from memory upon drop.

---

## ⚡ Technical Features

* **100% Memory-Safe Pure Rust Core (`crates/mirage-core`)**:
  * Native implementation with zero supply chain risk and zero open network sockets.
  * Rigorous memory hygiene with automatic memory wiping via the `Zeroize` trait.
* **Mirage-C4 v2 Cryptographic Cascade**:
  * 4 non-linear layers: **Camellia-256-CBC → ChaCha20 → ARIA-256-CBC → AES-256-GCM**.
  * Context-bound AEAD authentication tag (AAD binding).
* **Armored Key Derivation (TLV-KDF)**:
  * Injective Type-Length-Value encoding preventing canonical collision attacks.
  * High-memory **Scrypt** configuration ($N=131072, r=8, p=1$).
  * Subkey expansion using **HKDF-SHA256** with distinct cryptographic domain tags.
* **Shamir Secret Sharing (2-of-3)**:
  * Information-theoretic secret sharing over Galois Field $GF(2^8)$ with per-share HMAC-SHA256 verification.
* **Padmé Size Obfuscation**:
  * Length quantization with bounded $\le 12\%$ overhead (PETS 2019 standard) preventing metadata leakage from ciphertext size.
* **Carrier Steganography**:
  * Injects and extracts armored `.wraith` containers into PNG/JPEG image carriers.
* **Duress Decoy Mode**:
  * Supports decoy secondary passwords that decrypt a decoy document under duress scenarios.
* **GPU-Accelerated Desktop Interface (`mirage-gui`)**:
  * Native desktop UI built with `eframe`/`egui`.
  * Deep OLED Black (`#0A090F`) & Electric Purple theme.
  * Fully responsive centered layout adapting smoothly to window resizing.

---

## 🏗️ Project Architecture (100% Rust)

```
project-mirage/
├── Cargo.toml               # Cargo workspace definition
├── crates/
│   ├── mirage-core/         # Mirage-C4 v2, TLV-KDF, Shamir, Padmé cryptographic engine
│   │   ├── src/             # cascade.rs, kdf.rs, shamir.rs, padding.rs, format.rs, vault.rs, kat.rs
│   │   └── tests/           # Security integration and Known Answer Test (KAT) suites
│   ├── mirage-cli/          # High-performance standalone CLI binary (mirage)
│   └── mirage-gui/          # GPU-accelerated desktop application (mirage-gui)
├── assets/                  # Official application icons (wraith_icon.png, icon.icns)
├── release/                 # Prebuilt application bundles (Project Mirage.app)
├── install.py               # Universal environment installer for macOS & Windows
├── run.py                   # Multiplatform universal launcher (Python standard library)
├── mirage                   # Native 1-click launcher for macOS/Linux
├── mirage.bat / mirage.ps1  # Native 1-click launchers for Windows (CMD / PowerShell)
├── resources/               # Windows icon registry entries (.reg / .ico)
└── scripts/                 # Windows shell integration utilities
```

---

## 🚀 Quickstart

### 1. Automatic Environment Setup (macOS & Windows)
Run the universal installer script (automatically checks and installs Rust/Cargo if missing and builds release binaries):
```bash
python install.py
```

### 2. Launch the Desktop GUI

* **Universal (macOS & Windows):**
  ```bash
  python run.py
  ```
* **macOS:**
  ```bash
  ./mirage
  # or launch release/Project Mirage.app directly
  ```
* **Windows (PowerShell / CMD):**
  ```cmd
  .\mirage.bat
  ```
* **Directly via Cargo:**
  ```bash
  cargo run --release
  ```

---

## 💻 Command Line Interface (CLI)

```bash
# Encrypt a file using Mirage-C4 v2:
cargo run --release -p mirage-cli --bin mirage -- encrypt document.pdf --password "YourStrongSecretPassword123!#"

# Decrypt a .wraith container:
cargo run --release -p mirage-cli --bin mirage -- decrypt document.wraith --password "YourStrongSecretPassword123!#"

# Split a file into 3 Shamir shares (requires 2 to reconstruct):
cargo run --release -p mirage-cli --bin mirage -- split secret.zip --threshold 2 --total 3

# Combine shares to restore the file:
cargo run --release -p mirage-cli --bin mirage -- combine secret.part1.share secret.part2.share --output restored.zip

# Run Known Answer Tests (KAT) diagnostics:
cargo run --release -p mirage-cli --bin mirage -- test
```

---

## 🧪 Cryptographic Verification & Known Answer Tests (KAT)

All cryptographic algorithms are validated against official published vectors:

```bash
# Run all unit and security integration tests
cargo test --all
```

Official reference test vectors validated:
* **AES-256-GCM** (NIST GCM Test Cases 13 & 14)
* **ChaCha20 Keystream** (RFC 8439 §2.4.2)
* **Camellia-256** (RFC 3713 / NESSIE)
* **ARIA-256** (RFC 5794 §A.3)
* **HKDF-SHA256** (RFC 5869 Test Case 1)
* **scrypt** (RFC 7914 §12 ($N=16, r=1, p=1$))

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
