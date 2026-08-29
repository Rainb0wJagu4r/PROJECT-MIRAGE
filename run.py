#!/usr/bin/env python3
"""
PROJECT MIRAGE — Cross-Platform Universal Launcher (macOS / Windows / Linux)
Ejecuta la interfaz nativa en Rust o la suite de pruebas con un solo comando:
    python run.py
"""

import sys
import os
import subprocess
import shutil
import platform

def check_rust():
    cargo_path = shutil.which("cargo")
    if not cargo_path:
        # Check standard user cargo paths
        home = os.path.expanduser("~")
        candidate_cargo = os.path.join(home, ".cargo", "bin", "cargo.exe" if platform.system() == "Windows" else "cargo")
        if os.path.exists(candidate_cargo):
            os.environ["PATH"] = os.path.dirname(candidate_cargo) + os.pathsep + os.environ.get("PATH", "")
            return candidate_cargo
        return None
    return cargo_path

def main():
    print("\n========================================================")
    print(" 🛡️  PROJECT MIRAGE — ARMORED CRYPTOSYSTEM (RUST)")
    print(f" Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print("========================================================\n")

    cargo = check_rust()
    if not cargo:
        print("❌ Error: No se encontró el compilador de Rust (cargo) en tu sistema.\n")
        print("👉 Para instalar Rust automáticamente:")
        if platform.system() == "Windows":
            print("   Descarga e instala: https://win.rustup.rs/")
        else:
            print("   Ejecuta: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
        print("\nUna vez instalado, vuelve a ejecutar: python run.py\n")
        sys.exit(1)

    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    args = sys.argv[1:]

    if "--test" in args or "test" in args:
        print("🧪 Ejecutando suite de pruebas Known Answer Tests (KAT)...")
        cmd = [cargo, "run", "--release", "-p", "mirage-cli", "--bin", "mirage", "--", "test"]
    elif "--cli" in args or "cli" in args:
        print("💻 Ejecutando CLI de Project Mirage...")
        cli_args = [a for a in args if a not in ("--cli", "cli")]
        cmd = [cargo, "run", "--release", "-p", "mirage-cli", "--bin", "mirage", "--"] + cli_args
    else:
        print("🚀 Iniciando interfaz gráfica nativa en Rust (GPU acelerada)...")
        cmd = [cargo, "run", "--release"]

    try:
        res = subprocess.run(cmd)
        sys.exit(res.returncode)
    except KeyboardInterrupt:
        print("\n👋 Proceso finalizado por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error al ejecutar: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
