# Project Mirage

Project Mirage is a secure, desktop-grade local web application for symmetric file encryption using AES-256-GCM. It is designed to run entirely offline on loopback localhost, bypassing browser sandbox limitations while keeping private file data strictly on the host system.

## Features

- **AES-256-GCM Encryption**: Uses Node's native cryptographic library with 128-bit authentication tags to ensure absolute file integrity and detect tampering.
- **Bilingual Interface**: Toggles dynamically between English and Spanish.
- **Theme Controls**: Boots in Dark Mode with a high-fidelity toggle to Light Mode.
- **Real-time SHA3-256 Verification**: Instantly calculates and displays the SHA3-256 hash of selected local files before encryption and verifies hashes upon restoration.
- **Metadata Scrubbing**: Detects and strips tracking metadata tags from files prior to encryption:
  - **JPEG**: APP1 marker (GPS coordinates, camera model, author data).
  - **PNG**: Auxiliary text and timestamp chunks (tEXt, zTXt, iTXt, eXIf, tIME, pHYs).
- **Size Obfuscation**: Appends random bytes (exponential distribution up to 5MB) to hide the original file size.
- **Hardware-Locked KDF**: Binds file decryption to the host hardware platform UUID. The archive cannot be decrypted on other machines.
- **Time-To-Live (TTL)**: Embeds an expiration timestamp in the header. Once expired, the file refuses to decrypt and self-destructs.
- **Duress Mode**: Supports decoy passwords that restore a mock warning document instead of the confidential payload.
- **2-of-3 split fragmentation**: Encrypts and splits the archive into three parts. Any two components are sufficient to reconstruct the file.
- **Secure 3-Pass Shredder**: Wipes source files using multiple random passes and physical sector flushes before unlinking.

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
        └── AdvancedOptions.jsx # Encryption configuration toggles
```

## Getting Started

### Prerequisites

- Node.js (version 18.0.0 or higher)
- NPM

### Installation

1. Navigate to the project directory:
   ```bash
   cd project-mirage
   ```
2. Install the package dependencies:
   ```bash
   npm install
   ```

### Execution

To run the client and API server concurrently in development mode:

```bash
npm run dev
```

The application will be accessible at:
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:3001`

### Running the Test Suite

To verify the integrity of the cryptographic operations, run the automated test script:

```bash
node test-crypto.js
```

## Security Note on Time-to-Live (TTL)

The Time-to-Live (TTL) feature operates as an application-level filter. Because decryption keys are derived locally and the system runs offline on loopback localhost without a centralized key management server, the TTL restriction is a logic filter rather than a mathematical block. A user who makes a physical copy of the `.wraith` archive from the disk before the expiration timestamp occurs can preserve the original encrypted payload and bypass the application-level self-destruction routine.

