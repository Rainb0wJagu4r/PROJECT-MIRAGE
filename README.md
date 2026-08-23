# Project Mirage

Project Mirage is a secure, desktop-grade local web application for symmetric file encryption using AES-256-GCM and Mirage-C4. It is designed to run entirely offline on loopback localhost, bypassing browser sandbox limitations while keeping private file data strictly on the host system.

---

## Technical Features

- **Armored Cryptography**: Uses Node's native cryptographic library with 128-bit authentication tags to ensure absolute file integrity and detect physical or logical tampering.
- **AES-256-GCM Encryption**: High-speed symmetric authenticated encryption standard.
- **Mirage-C4 Cascade Cipher**: A 4-layer cryptographic cascade (4×256-bit) chaining Camellia-256-CTR, ARIA-256-CTR, ChaCha20, and AES-256-GCM with individual scrypt key derivations.
- **Bilingual Interface**: Toggles dynamically between English and Spanish.
- **Theme Controls**: Boots in Dark Mode with a high-fidelity toggle to Light Mode.
- **Real-time SHA3-256 Verification**: Instantly calculates and displays the SHA3-256 hash of selected local files before encryption and verifies hashes upon restoration.
- **Metadata Scrubbing**: Detects and strips tracking metadata tags from files prior to encryption:
  - **JPEG**: APP1 marker (GPS coordinates, camera model, author data).
  - **PNG**: Auxiliary text and timestamp chunks (tEXt, zTXt, iTXt, eXIf, tIME, pHYs).
- **Size Obfuscation**: Appends random bytes (exponential distribution up to 5MB) to hide the original file size.
- **Hardware-Locked KDF**: Binds file decryption to the host hardware platform UUID (using system queries or cryptographic registry keys). The archive cannot be decrypted on other machines.
- **Time-To-Live (TTL)**: Embeds an expiration timestamp in the header. Once expired, the file refuses to decrypt and self-destructs.
- **Duress Mode**: Supports decoy passwords that restore a mock warning document instead of the confidential payload.
- **2-of-3 split fragmentation**: Encrypts and splits the archive into three parts. Any two components are sufficient to reconstruct the file.
- **Secure Shredder**: Overwrites source files in multiple random passes and physical sector flushes before unlinking.
- **Carrier Appending (Encapsulation)**: Invisibly appends the encrypted payload to the end of a carrier image (PNG/JPEG) so it remains 100% viewable without revealing the payload.

---

## Project Structure

```
project-mirage/
├── package.json         # Run script declarations and dependencies
├── vite.config.js       # React development server proxy settings
├── server.js            # Express API server handling crypto operations
├── index.html           # Main template configuration
├── test-crypto.js       # Test suite for backend cryptography operations
└── src/
    ├── main.jsx         # Client entry point
    ├── index.css        # Stylesheet overrides (Light/Dark themes)
    ├── App.jsx          # React state coordination and UI layouts
    └── components/
        ├── Dropzone.jsx # File drag-and-drop handler
        ├── PathInput.jsx# Local file path selector
        ├── AdvancedOptions.jsx # Encryption configuration toggles
        └── StegoConsole.jsx # Carrier Appending interface console
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

To verify the cryptographic primitives and KDF routines, run the automated test suite in your shell:
```bash
node test-crypto.js
```
All tests should return `PASS`.
