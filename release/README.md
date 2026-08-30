# 📦 PROJECT MIRAGE — RELEASE PACKAGES (v2.2.0)

Este directorio contiene los paquetes y ejecutables de distribución oficiales de **Project Mirage** (100% Rust Nativo, Cero Vulnerabilidades de Supply Chain).

---

## 🍏 macOS (Apple Silicon M1/M2/M3/M4 & Intel)

* **`ProjectMirage-macOS-v2.2.0.dmg`**: Imagen de disco instalable. Ábrela y arrastra *Project Mirage* a tu carpeta de Aplicaciones.
* **`Project Mirage.app`**: Paquete de aplicación de macOS listo para abrir con doble clic.

---

## 🪟 Windows 10 / 11 (x64)

Para generar el ejecutable nativo `.exe` en Windows:

1. Ejecuta el instalador automático si es la primera vez:
   ```cmd
   python install.py
   ```
2. Compila el ejecutable `.exe` nativo:
   ```cmd
   cargo build --release --bin mirage-gui
   ```
3. El archivo ejecutable quedará disponible en:
   `target\release\mirage-gui.exe` (puedes renombrarlo a `ProjectMirage.exe` y colocarlo en esta carpeta `release\`).
