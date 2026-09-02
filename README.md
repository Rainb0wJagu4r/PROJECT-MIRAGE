# Project Mirage // Armored Cryptosystem (Rust LTS)

[![FileInfo.com Verified](https://img.shields.io/badge/FileInfo.com-.WRAITH_Registered-8A2BE2?style=for-the-badge&logo=checkmarx&logoColor=white)](https://fileinfo.com/extension/wraith)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Tests: 100% Pass](https://img.shields.io/badge/KAT_Tests-100%25_PASS-brightgreen?style=for-the-badge)](crates/mirage-core/tests/security_tests.rs)

> 🏆 **Formato Oficial Reconocido en FileInfo.com**  
> La extensión **`.wraith`** (Wraith Encrypted File / Project Mirage Encrypted Archive) y el sistema criptográfico **Mirage-C4** han sido reconocidos e indexados oficialmente en la base de datos global de formatos de archivo:  
> 👉 [https://fileinfo.com/extension/wraith](https://fileinfo.com/extension/wraith)  
>  
> *"A WRAITH file is an encrypted file created by Project Mirage, an open-source desktop encryption application that protects files stored on a local computer. It stores a single file encrypted with AES-256-GCM and the Mirage-C4 encryption system, protected by a password the creator specifies during encryption."* — **FileInfo.com**

---

**Project Mirage** es un sistema criptográfico simétrico acorazado y una suite de escritorio desarrollada **100% en Rust**, diseñada para ofrecer protección de datos con **cero dependencias de Node/NPM, cero servidores de red en tiempo de ejecución y cero vectores de ataque de Supply Chain**.

> [!WARNING]
> **Project Origin & Active Development Status**
> - 🇲🇽 **Born in Mexico:** This project is proud to be born in Mexico.
> - **In Development:** The software is actively maintained as an open-source armored cryptosystem.
> - **Statistical tests (NIST SP 800-22):** The output of `.wraith` archives passes the SP 800-22 suite: [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).
> - **Pure Rust Migration:** Completely migrated from JavaScript to 100% native Rust (`crates/mirage-core`), eliminating immutable string memory persistence and runtime supply chain vulnerabilities. Intermediate key buffers are wiped with the `Zeroize` trait.

---

## ⚡ Características Técnicas

* **Criptografía 100% en Rust Nativo**:
  * Implementación estricta y segura en memoria (`crates/mirage-core`).
  * Sin riesgo de ataques a la cadena de suministro (*Zero Supply Chain Attack Vector*).
  * Limpieza estricta de memoria RAM para claves maestras y subllaves con el trait `Zeroize`.
* **Cascada Criptográfica Mirage-C4 v2**:
  * 4 capas no lineales: **Camellia-256-CBC → ChaCha20 → ARIA-256-CBC → AES-256-GCM**.
  * Autenticación AEAD vinculada al contexto (Context-bound AAD).
* **Derivación de Claves Blindada (TLV-KDF)**:
  * Codificación inyectiva Type-Length-Value sin colisiones.
  * **Scrypt** con parámetros de alta memoria ($N=131072, r=8, p=1$).
  * Expansión de subllaves con **HKDF-SHA256** y dominios separados.
* **Fragmentación Secreta de Shamir (2-de-3)**:
  * Implementación sobre el campo de Galois $GF(2^8)$ con HMAC-SHA256 por fragmento.
* **Ofuscación de Tamaño (Padmé Quantization)**:
  * Cuantización de longitud con sobrecoste acotado ($\le 12\%$, estándar PETS 2019).
* **Esteganografía Portadora**:
  * Capacidad de ocultar o inyectar contenedores `.wraith` dentro de imágenes PNG o JPEG.
* **Modo Coacción (Duress Decoy)**:
  * Admite contraseñas señuelo para restaurar un documento ficticio ante situaciones de coacción.
* **Interfaz Gráfica GPU Acelerada (`mirage-gui`)**:
  * Tema Dark OLED (`#0A090F`) y Electric Purple.
  * Diseño 100% responsivo con adaptación automática al redimensionar la ventana.
  * Carga e integración del logo oficial de Project Mirage.

---

## 🏗️ Estructura del Repositorio (100% Rust)

```
project-mirage/
├── Cargo.toml               # Configuración del workspace de Cargo
├── crates/
│   ├── mirage-core/         # Núcleo criptográfico Mirage-C4 v2, TLV-KDF, Shamir, Padmé
│   │   ├── src/             # cascade.rs, kdf.rs, shamir.rs, padding.rs, format.rs, vault.rs, kat.rs
│   │   └── tests/           # Suites de pruebas de seguridad e integración adversarial
│   ├── mirage-cli/          # Binario CLI nativo de alta velocidad (mirage)
│   └── mirage-gui/          # Aplicación de escritorio nativa acelerada por GPU (eframe/egui)
├── assets/                  # Iconos oficiales (icon.png, wraith_logo.png, icon.icns)
├── release/                 # Paquetes de distribución listos para usar (Project Mirage.app)
├── install.py               # Instalador universal automático para macOS y Windows
├── run.py                   # Lanzador multiplataforma en 1 comando (Python Standard Library)
├── mirage                   # Script ejecutable directo para macOS/Linux
├── mirage.bat / mirage.ps1  # Scripts ejecutables directos para Windows
├── resources/               # Registro de Windows para asociar la extensión .wraith
└── scripts/                 # Utilidades de registro de iconos en el Explorador de Windows
```

---

## 🚀 Inicio Rápido (Quickstart)

### 1. Instalación Automática (Windows y macOS)
Ejecuta el instalador en un solo paso (detecta el SO, instala Rust/Cargo automáticamente si no están instalados y compila el proyecto):
```bash
python install.py
```

### 2. Iniciar la Interfaz Gráfica (Desktop GUI)

* **Multiplataforma (Recomendado):**
  ```bash
  python run.py
  ```
* **macOS:**
  ```bash
  ./mirage
  # o abriendo directamente: release/Project Mirage.app
  ```
* **Windows (PowerShell o CMD):**
  ```cmd
  .\mirage.bat
  ```
* **Directamente con Cargo:**
  ```bash
  cargo run --release
  ```

---

## 💻 Uso de la Línea de Comandos (CLI)

```bash
# Cifrar un archivo con Mirage-C4 v2:
cargo run --release -p mirage-cli --bin mirage -- encrypt documento.pdf --password "TuContraseñaSecreta!#"

# Descifrar un archivo .wraith:
cargo run --release -p mirage-cli --bin mirage -- decrypt documento.wraith --password "TuContraseñaSecreta!#"

# Dividir un archivo en 3 fragmentos (requiere 2 para reconstruir):
cargo run --release -p mirage-cli --bin mirage -- split archivo.zip --threshold 2 --total 3

# Recombinar fragmentos:
cargo run --release -p mirage-cli --bin mirage -- combine archivo.part1.share archivo.part2.share --output restaurado.zip

# Ejecutar las pruebas Known Answer Tests (KAT):
cargo run --release -p mirage-cli --bin mirage -- test
```

---

## 🧪 Pruebas y Verificación Criptográfica

Todas las pruebas criptográficas están implementadas nativamente en Rust:

```bash
# Ejecutar toda la suite de pruebas unitarias y adversariales
cargo test --all
```

Vectores de prueba de referencia incluidos (Known Answer Tests):
* **AES-256-GCM** (NIST GCM Test Cases 13 y 14)
* **ChaCha20** (RFC 8439 §2.4.2)
* **Camellia-256** (RFC 3713 / NESSIE)
* **ARIA-256** (RFC 5794 §A.3)
* **HKDF-SHA256** (RFC 5869 Test Case 1)
* **scrypt** (RFC 7914 §12 ($N=16, r=1, p=1$))

---

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
