# Project Mirage

Project Mirage is a secure, desktop-grade local web application for symmetric file encryption using AES-256-GCM and Mirage-C4. It is designed to run entirely offline on loopback localhost, bypassing browser sandbox limitations while keeping private file data strictly on the host system.

> [!WARNING]
> **Project Origin & Active Development Status**
> - 🇲🇽 **Born in Mexico:** This project is proud to be born in Mexico.
> - **In Development:** The software is still under active development and should be treated as experimental.
> - **Statistical tests (NIST SP 800-22):** the output of `.wraith` archives passes
>   the SP 800-22 suite: [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).
>   **Read this carefully:** SP 800-22 measures whether output *looks* random. It is
>   **not** evidence of cryptographic security. Proof: the v1 cascade passed these
>   tests while collapsing to a single XOR and being trivially breakable
>   (see [`DEPRECATED.md`](DEPRECATED.md)). Passing is a *necessary* condition, never a sufficient one.
> - **Round-3 security review (2026):** 18 findings, all empirically confirmed; 13 fixed.
>   See [Known limitations](#known-limitations) and [`DEPRECATED.md`](DEPRECATED.md).
> - **Open to Audits:** This project is open to public security audits and code reviews. We highly appreciate any feedback, contributions, or advice to help us continue learning and working on secure cryptographic applications.

---

## Technical Features

- **Armored Cryptography**: Uses Node's native cryptographic library with 128-bit authentication tags to ensure absolute file integrity and detect physical or logical tampering.
- **AES-256-GCM Encryption**: High-speed symmetric authenticated encryption standard.
- **Mirage-C4 cascade (v2)**: 4 layers — Camellia-256-**CBC** → ChaCha20 → ARIA-256-**CBC**
  → AES-256-GCM. Subkeys derived via scrypt + HKDF with domain separation.
  The first two layers are CBC on purpose: in v1 all four layers were stream ciphers,
  so the cascade collapsed to `P xor KS`.
  **Real benefit:** defence in depth if one of the four ciphers is broken in the future.
  **It does not add up key sizes: security is ~256 bits (~128 vs Grover), the same as AES-256.**
- **Bilingual Interface**: Toggles dynamically between English and Spanish.
- **Theme Controls**: Boots in Dark Mode with a high-fidelity toggle to Light Mode.
- **Real-time SHA3-256 Verification**: Instantly calculates and displays the SHA3-256 hash of selected local files before encryption and verifies hashes upon restoration.
- **Metadata Scrubbing**: Detects and strips tracking metadata tags from files prior to encryption:
  - **JPEG**: APP1 marker (GPS coordinates, camera model, author data).
  - **PNG**: Auxiliary text and timestamp chunks (tEXt, zTXt, iTXt, eXIf, tIME, pHYs).
- **Size obfuscation (Padmé)**: length quantization with bounded ~12% overhead (Nikitin et al., PETS 2019; used by Signal/PURBs). It **reduces** the size leak, it does not eliminate it.
- **Hardware-Locked KDF**: Binds file decryption to the host hardware platform UUID (using system queries or cryptographic registry keys). The archive cannot be decrypted on other machines.
- **Time-To-Live (TTL)**: embeds an expiration timestamp. Checked before returning or writing any data. **It is not a cryptographic control** — see [Known limitations](#known-limitations).
- **Duress Mode**: Supports decoy passwords that restore a mock warning document instead of the confidential payload.
- **2-of-3 fragmentation (Shamir)**: real Shamir Secret Sharing over GF(2^8) with per-share HMAC. Any two shares reconstruct the file; a single share reveals **nothing** (information-theoretic). In v1 this was XOR parity and share 1 leaked the header in the clear.
- **Secure shredder**: multiple random overwrite passes before unlinking. **No guarantee on SSD/NVMe, copy-on-write filesystems, or with snapshots** — see [Known limitations](#known-limitations).
- **Pure Rust Cryptographic Engine**:
  - `crates/mirage-core`: 100% memory-safe Rust library implementing the full Mirage-C4 v2 specification, TLV-KDF, Shamir 2-of-3, Padmé quantization, and container serialization. Eliminates JavaScript supply chain attack vectors and guarantees key zeroization in RAM with the `Zeroize` trait.
  - `crates/mirage-cli`: Native, standalone command-line binary (`mirage`) for fast encryption, decryption, and integrity testing.

---

## Project Structure

```
project-mirage/
├── Cargo.toml           # Rust workspace definition
├── crates/
│   ├── mirage-core/     # 100% Memory-Safe Core Cryptography (Rust)
│   │   ├── src/         # kdf.rs, cascade.rs, format.rs, shamir.rs, padding.rs, vault.rs, kat.rs
│   │   └── tests/       # Adversarial and Known Answer Test suites (Rust)
│   └── mirage-cli/      # High-performance CLI binary (mirage)
├── package.json         # Web GUI dependencies & run scripts
├── vite.config.js       # Vite client bundler
├── server.js            # Local loopback server
└── src/                 # React Cyberpunk GUI
```

---

## Getting Started

### Prerequisites

* **Node.js** (version 18.0.0 up to version 26.x.x or higher)
* **NPM** (packaged with Node.js)
* **Git** (for downloading/updating the project)

---

## Step-by-Step Guide: macOS

### 1. Open Terminal
Press `Cmd + Space`, type `Terminal`, and press `Enter`.

### 2. Clone/Navigate to the Repo
Navigate to the directory containing the project:
```bash
cd /path/to/project-mirage
```

### 3. Install Dependencies
Run:
```bash
npm install
```

### 4. Run Development Environment
Start both the Express API backend and the Vite client concurrently:
```bash
npm run dev
```
Open your browser and navigate to:
* **Frontend GUI:** `http://localhost:5173`

---

## Step-by-Step Guide: Windows

### 1. Open PowerShell or Command Prompt
Press `Win + X` and select **Terminal** (or search for **PowerShell** in the Start menu).

### 2. Navigate to the Repo
Navigate to the folder:
```powershell
cd C:\path\to\project-mirage
```

### 3. Install Dependencies
Run:
```powershell
npm install
```

### 4. Run Development Environment
Start the development server:
```powershell
npm run dev
```
Open your browser and navigate to:
* **Frontend GUI:** `http://localhost:5173`

---

## Development vs Production Environments

* **Development Mode (`npm run dev`)**: Launches a development server on port 5173 proxying API requests to the Express backend (port 3001). 
* **Production Packaging (`npm run app:package`)**: Packages the application into an offline-ready standalone desktop executable bundle using Electron.

---

## Troubleshooting

### 1. Port Collision (Address Already in Use)
If you see an error indicating port `5173` or `3001` is already in use, find and kill the process:
* **macOS:**
  ```bash
  kill -9 $(lsof -t -i:3001)
  ```
* **Windows:**
  ```powershell
  Stop-Process -Id (Get-NetTCPConnection -LocalPort 3001).OwningProcess -Force
  ```

### 2. Proxy Error / AggregateError ECONNREFUSED
If the Vite UI loads but the console widget shows `OFFLINE` or request errors:
* Check the terminal where `npm run dev` was executed. Make sure that the backend `server.js` starts up successfully and prints:
  `Project Mirage Local API Server online!`
* If you are running without local SSL keys, Vite's proxy automatically detects this and points to the `http://` backend rather than `https://`.

---

## Verification and Testing

### 1. Pure Rust Core Test Suite & Known Answer Tests (KAT)
```bash
# Run all native Rust unit and integration security tests
cargo test --all

# Run the standalone Rust CLI KAT diagnostics
cargo run --release --bin mirage -- test
```

### 2. Standalone Rust CLI Quickstart
```bash
# Build release binary
cargo build --release

# Encrypt a file (default: Mirage-C4 v2 non-linear cascade)
./target/release/mirage encrypt secret.pdf --password "YourStrongPassword123!#"

# Decrypt a .wraith file
./target/release/mirage decrypt secret.wraith --password "YourStrongPassword123!#"
```

### 3. Web Development Test Suite
```bash
# Run security test suite
npm test

# Run KAT checks
npm run test:kat
```

All test suites should complete with 100% passing results.

---

## Known limitations

Honest list of what this project does **not** protect against. If you rely on
Mirage for something that matters, read this section before the feature list.

### Not a cryptographic control

| Feature | What it actually does | What it does **not** do |
|---|---|---|
| **TTL / expiration** | The reference client refuses to decrypt after the date. | Does not stop anyone. The timestamp is inside the authenticated payload, so whoever holds the file **and the password** can read it with another client, or by moving the system clock. Treat it as a hint, never as a guarantee. |
| **Duress mode** | Two independent blocks; the decoy password opens harmless content. | Does not hide *that a second block exists*. The file size and structure reveal there are two blocks. It resists a casual look, **not** forensic analysis by someone who knows the format. |
| **Secure shredder** | Overwrites the file in place with random passes. | **No guarantee on SSD/NVMe** (wear levelling relocates blocks), on copy-on-write filesystems (Btrfs, ZFS, APFS), with snapshots, journals, backups, or `Volume Shadow Copy` on Windows. Full-disk encryption is a better answer for this. |
| **Steganography (PNG/JPEG)** | Appends the payload after the end of the carrier image. | **This is not steganography.** The data is trivially detectable by anyone who looks past the image's end marker. It hides from a casual viewer, not from analysis. |
| **Hardware lock** | Binds decryption to the machine's UUID. | If you change machine, motherboard, or reinstall, **you lose access permanently.** Do not use it for archives you need to move. |

### Bounded, not eliminated

- **Size leak (Padmé).** Quantization limits overhead to ~12% and lumps files
  into buckets, but the bucket itself is public. Two very different files land
  in the same bucket; a 4 KB file and a 4 GB file do not.
- **Password strength.** The heuristic estimates entropy and rejects weak
  input, but it accepts things like `Password123!` (it has length, mixed case,
  digits and a symbol). Entropy estimation on human passwords is an
  approximation, not a measurement. **Use a passphrase from a password manager.**
- **Key zeroization.** `lib/kdf.js` wipes intermediate `Buffer`s, but
  **JavaScript strings are immutable**: the password itself cannot be reliably
  erased from memory. A memory dump or swap file may retain it. This is a
  limitation of the runtime, not something the code can fix.
- **Timing.** Error handling is uniform and token comparison is
  constant-time, but no formal timing analysis has been done under load.

### Addressed & Architecture Evolution

- **Native Electron IPC & Hybrid Browser Architecture (MIRAGE-012 Resolved)**:
  - Eliminated hardcoded tokens. The desktop application uses native Electron IPC via `contextBridge` with zero open HTTP sockets.
  - In local development mode, a local loopback server supports browser workflows seamlessly.
- **Standalone Algorithm Library**:
  - `mirage-c4-lib` packaged as a standalone ESM library with CLI utilities.
  - Core cryptographic cascade, AAD binding, Shamir secret sharing, and KDF algorithms in `lib/*.js` remain 100% untouched and verified across 73/73 test suites.

### What the tests do and do not prove

```bash
npm test           # 73 adversarial cases
npm run test:kat   # 11 published vectors (RFC 8439, 5794, 3713, 5869, 7914, NIST SP 800-38A/D)
node avalanche_test.js
```

All of them passing means **known regressions have not come back** and the
primitives are invoked correctly. It does **not** mean the system is secure.
No amount of passing tests proves the absence of flaws — the v1 cascade passed
statistical tests while being trivially breakable.

**This project has not been audited by a professional cryptography firm.** It
is a self-designed construction, and self-designed cryptography carries risk
regardless of how carefully it is written. For protecting information whose
disclosure would cause you serious harm, prefer audited, widely reviewed tools
(age, GnuPG, VeraCrypt).

Reports and reviews are welcome — that is why this section exists.
