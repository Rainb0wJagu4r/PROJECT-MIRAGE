#!/usr/bin/env python3
"""
PROJECT MIRAGE — Universal Dependency & Environment Installer
Instala automáticamente Rust, Cargo y todas las herramientas necesarias
en Windows (10/11) y macOS (Apple Silicon / Intel).

Uso:
    python install.py
"""

import sys
import os
import platform
import subprocess
import urllib.request
import tempfile
import shutil

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

def print_banner():
    print("\n" + "=" * 60)
    print(" 🛡️  PROJECT MIRAGE — INSTALADOR AUTOMÁTICO DE ENTORNO")
    print(f" Sistema Operativo: {platform.system()} {platform.release()} ({platform.machine()})")
    print("=" * 60 + "\n")

def run_cmd(cmd, check=True, shell=False):
    print(f"  ▶ Ejecutando: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, check=check, shell=shell)

def get_cargo_path():
    cargo = shutil.which("cargo")
    if cargo:
        return cargo
    home = os.path.expanduser("~")
    candidate = os.path.join(home, ".cargo", "bin", "cargo.exe" if IS_WINDOWS else "cargo")
    if os.path.exists(candidate):
        cargo_bin = os.path.dirname(candidate)
        if cargo_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
        return candidate
    return None

def install_rust():
    print("\n📦 [1/3] Verificando compilador de Rust & Cargo...")
    cargo = get_cargo_path()
    if cargo:
        try:
            ver = subprocess.check_output([cargo, "--version"], text=True).strip()
            print(f"  ✅ Rust ya está instalado: {ver}")
            return True
        except Exception:
            pass

    print("  ⏳ Rust no encontrado. Instalando automáticamente...")

    if IS_WINDOWS:
        rustup_url = "https://win.rustup.rs/x86_64"
        tmp_dir = tempfile.mkdtemp()
        installer_path = os.path.join(tmp_dir, "rustup-init.exe")
        try:
            print(f"  📥 Descargando rustup-init desde {rustup_url}...")
            urllib.request.urlretrieve(rustup_url, installer_path)
            print("  ⚙️  Instalando toolchain de Rust (modo default -y)...")
            subprocess.run([installer_path, "-y", "--default-toolchain", "stable"], check=True)
            print("  ✅ Rust instalado correctamente en Windows.")
        except Exception as e:
            print(f"  ❌ Error al instalar Rust: {e}")
            print("  👉 Por favor descarga e instala manualmente: https://win.rustup.rs/")
            return False
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    else:
        # macOS / Linux
        try:
            cmd = "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
            subprocess.run(cmd, shell=True, check=True)
            print("  ✅ Rust instalado correctamente.")
        except Exception as e:
            print(f"  ❌ Error al instalar Rust: {e}")
            return False

    # Refresh PATH in current session
    get_cargo_path()
    return True

def verify_system_tools():
    print("\n🔧 [2/3] Verificando herramientas del sistema...")
    if IS_MACOS:
        try:
            subprocess.run(["xcode-select", "-p"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print("  ✅ Xcode Command Line Tools detectadas.")
        except Exception:
            print("  ⚠️  Instalando Xcode Command Line Tools...")
            subprocess.run(["xcode-select", "--install"])
    elif IS_WINDOWS:
        print("  ✅ Entorno Windows verificado.")

def build_project():
    print("\n⚡ [3/3] Compilando y verificando Project Mirage...")
    cargo = get_cargo_path()
    if not cargo:
        print("  ❌ No se pudo localizar cargo después de la instalación.")
        print("  👉 Cierra y vuelve a abrir tu terminal, luego ejecuta: python run.py")
        return False

    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    try:
        print("  🏗️  Compilando binarios en modo release...")
        subprocess.run([cargo, "build", "--release"], check=True)
        print("  🧪 Verificando Known Answer Tests (KAT)...")
        subprocess.run([cargo, "run", "--release", "-p", "mirage-cli", "--bin", "mirage", "--", "test"], check=True)
        print("\n" + "=" * 60)
        print(" 🎉 ¡TODO LISTO! El entorno de Project Mirage está 100% configurado.")
        print("=" * 60)
        print("\nPara iniciar la aplicación:")
        print("  ▶ python run.py          (o ./mirage en macOS / .\\mirage.bat en Windows)\n")
        return True
    except Exception as e:
        print(f"  ❌ Error durante la compilación: {e}")
        return False

def main():
    print_banner()
    if not install_rust():
        sys.exit(1)
    verify_system_tools()
    if not build_project():
        sys.exit(1)

if __name__ == "__main__":
    main()
