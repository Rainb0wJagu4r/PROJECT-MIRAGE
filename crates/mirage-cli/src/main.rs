use clap::{Parser, Subcommand};
use colored::*;
use mirage_core::format::{
    append_to_carrier, deserialize_payload, extract_from_carrier, serialize_payload,
};
use mirage_core::kat::run_known_answer_tests;
use mirage_core::paths::safe_basename;
use mirage_core::shamir::{combine_shares, split_secret};
use mirage_core::vault::{
    decrypt_vault, encrypt_vault, Algorithm, DecryptVaultOptions, EncryptVaultOptions,
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mirage",
    author = "Project Mirage Contributors",
    version = "2.2.0-rust",
    about = "Project Mirage: Armored Symmetric Cryptosystem (Mirage-C4 v2) & Vault CLI in Rust",
    long_about = "High-performance, 100% memory-safe symmetric encryption CLI implementing Mirage-C4 v2 (Camellia-CBC + ChaCha20 + ARIA-CBC + AES-GCM), Shamir Secret Sharing, and Padmé size obfuscation."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cifrar un archivo con Mirage-C4 v2 o AES-256-GCM
    Encrypt {
        /// Ruta del archivo a cifrar
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Contraseña maestra (mínimo 12 caracteres recomendados)
        #[arg(short, long)]
        password: String,

        /// Segundo factor simétrico (opcional)
        #[arg(long)]
        second_factor: Option<String>,

        /// Algoritmo: mirage-c4 o aes-gcm
        #[arg(short, long, default_value = "mirage-c4")]
        algo: String,

        /// Ruta de salida personalizada
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Dividir en fragmentos 2-de-3 (Shamir Secret Sharing)
        #[arg(long)]
        split: bool,

        /// Ocultar dentro de una imagen portadora (esteganografía)
        #[arg(long)]
        carrier: Option<PathBuf>,

        /// Contraseña señuelo (activa modo duress)
        #[arg(long)]
        duress_password: Option<String>,

        /// Archivo señuelo para modo duress
        #[arg(long)]
        duress_file: Option<PathBuf>,
    },

    /// Descifrar un archivo .wraith o fragmentos .share
    Decrypt {
        /// Archivo cifrado (.wraith) o fragmentos (.share)
        #[arg(value_name = "FILES", required = true)]
        files: Vec<PathBuf>,

        /// Contraseña para descifrar
        #[arg(short, long)]
        password: String,

        /// Segundo factor simétrico (si fue habilitado)
        #[arg(long)]
        second_factor: Option<String>,

        /// Ruta o directorio de destino para guardar el archivo restaurado
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Ejecutar suite de Known Answer Tests (KAT) y pruebas de autodiagnóstico
    Test,

    /// Dividir un archivo arbitrario con Shamir 2-de-3
    Split {
        /// Archivo a fragmentar
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Umbral mínimo de fragmentos para reconstruir (default: 2)
        #[arg(short, long, default_value_t = 2)]
        threshold: u8,

        /// Número total de fragmentos a generar (default: 3)
        #[arg(short, long, default_value_t = 3)]
        total: u8,
    },

    /// Recombinar fragmentos de Shamir
    Combine {
        /// Lista de fragmentos (.share)
        #[arg(value_name = "SHARES", required = true)]
        shares: Vec<PathBuf>,

        /// Ruta de salida para el archivo reconstruido
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            file,
            password,
            second_factor,
            algo,
            output,
            split,
            carrier,
            duress_password,
            duress_file,
        } => {
            println!("{}", "🛡️  PROJECT MIRAGE — CIFRADO DE ARCHIVOS".bright_cyan().bold());
            println!("{}", "--------------------------------------------------------".dimmed());

            if !file.exists() {
                eprintln!("{}: No se encuentra el archivo {:?}", "Error".red().bold(), file);
                std::process::exit(1);
            }

            let file_bytes = match fs::read(&file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}: No se pudo leer el archivo: {e}", "Error".red().bold());
                    std::process::exit(1);
                }
            };

            let filename = file.file_name().unwrap().to_str().unwrap();
            let payload = match serialize_payload(filename, &file_bytes, 0) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}: {}", "Error de formato".red().bold(), e.public_message());
                    std::process::exit(1);
                }
            };

            let mut decoy_payload = None;
            if let Some(df) = &duress_file {
                if let Ok(df_bytes) = fs::read(df) {
                    let df_name = df.file_name().unwrap().to_str().unwrap();
                    decoy_payload = serialize_payload(df_name, &df_bytes, 0).ok();
                }
            }

            let algorithm = if algo.to_lowercase() == "aes-gcm" {
                Algorithm::AesGcm
            } else {
                Algorithm::CascadeC4
            };

            println!("🔒 Cifrando: {} ({} bytes)", filename.yellow(), file_bytes.len());
            println!("⚙️  Algoritmo: {}", if algorithm == Algorithm::CascadeC4 { "Mirage-C4 v2 (4 capas CBC+ChaCha+GCM)".green() } else { "AES-256-GCM".green() });

            let enc_res = match encrypt_vault(EncryptVaultOptions {
                payload: &payload,
                decoy_payload: decoy_payload.as_deref(),
                password: &password,
                second_factor: second_factor.as_deref(),
                duress_password: duress_password.as_deref(),
                hardware_id: None,
                algorithm,
                bucket_padding: true,
                is_vault: false,
            }) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("{}: {}", "Fallo de cifrado".red().bold(), e.public_message());
                    std::process::exit(1);
                }
            };

            let mut final_data = enc_res.envelope;

            if let Some(c_path) = carrier {
                if let Ok(c_bytes) = fs::read(&c_path) {
                    final_data = append_to_carrier(&c_bytes, &final_data);
                    println!("🖼️  Encapsulado dentro de imagen portadora: {:?}", c_path);
                }
            }

            if split {
                println!("🧩 Dividiendo en fragmentos 2-de-3 (Shamir Secret Sharing)...");
                let shares = match split_secret(&final_data, 2, 3) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{}: {}", "Fallo en Shamir".red().bold(), e.public_message());
                        std::process::exit(1);
                    }
                };

                let base_name = file.file_stem().unwrap().to_str().unwrap();
                for (i, share) in shares.iter().enumerate() {
                    let share_path = PathBuf::from(format!("{base_name}.part{}.share", i + 1));
                    fs::write(&share_path, share).unwrap();
                    println!("  ✨ Fragmento guardado: {:?}", share_path);
                }
                println!("{}", "✅ Cifrado y fragmentación completados con éxito.".bright_green().bold());
            } else {
                let default_out = file.with_extension("wraith");
                let out_path = output.unwrap_or(default_out);
                if let Err(e) = fs::write(&out_path, &final_data) {
                    eprintln!("{}: No se pudo guardar el archivo: {e}", "Error".red().bold());
                    std::process::exit(1);
                }
                println!("💾 Archivo cifrado guardado en: {}", out_path.display().to_string().bright_green());
                println!("{}", "✅ Operación completada con éxito.".bright_green().bold());
            }
        }

        Commands::Decrypt {
            files,
            password,
            second_factor,
            output,
        } => {
            println!("{}", "🔓  PROJECT MIRAGE — DESCIFRADO DE ARCHIVOS".bright_cyan().bold());
            println!("{}", "--------------------------------------------------------".dimmed());

            let mut raw_data = Vec::new();

            if files.len() > 1 || files[0].extension().map_or(false, |ext| ext == "share") {
                println!("🧩 Recomponiendo {} fragmentos de Shamir...", files.len());
                let mut share_buffers = Vec::new();
                for f in &files {
                    match fs::read(f) {
                        Ok(b) => share_buffers.push(b),
                        Err(e) => {
                            eprintln!("{}: No se pudo leer {:?}: {e}", "Error".red().bold(), f);
                            std::process::exit(1);
                        }
                    }
                }
                let share_slices: Vec<&[u8]> = share_buffers.iter().map(|b| b.as_slice()).collect();
                raw_data = match combine_shares(&share_slices) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("{}: {}", "Error al reconstruir fragmentos".red().bold(), e.public_message());
                        std::process::exit(1);
                    }
                };
            } else {
                raw_data = match fs::read(&files[0]) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("{}: No se pudo leer el archivo: {e}", "Error".red().bold());
                        std::process::exit(1);
                    }
                };
            }

            // Extract from carrier if steg
            let (envelope, was_steg) = extract_from_carrier(&raw_data).unwrap_or((raw_data, false));
            if was_steg {
                println!("🖼️  Envoltorio extraído de imagen portadora.");
            }

            println!("🔑 Descifrando contenedor...");
            let dec = match decrypt_vault(
                &envelope,
                DecryptVaultOptions {
                    password: &password,
                    second_factor: second_factor.as_deref(),
                    hardware_id: None,
                },
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{}: {}", "Fallo de autenticación".red().bold(), e.public_message());
                    std::process::exit(1);
                }
            };

            if dec.is_duress {
                println!("{}", "⚠️  AVISO: Contenido señuelo restaurado (modo coacción).".yellow().bold());
            }

            let payload = match deserialize_payload(&dec.payload) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}: {}", "Error al procesar archivo".red().bold(), e.public_message());
                    std::process::exit(1);
                }
            };

            let out_file_name = safe_basename(&payload.filename, "restored.bin");
            let target_path = if let Some(out_p) = output {
                if out_p.is_dir() {
                    out_p.join(out_file_name)
                } else {
                    out_p
                }
            } else {
                PathBuf::from(format!("restored_{out_file_name}"))
            };

            if let Err(e) = fs::write(&target_path, &payload.file_data) {
                eprintln!("{}: No se pudo escribir el archivo restaurado: {e}", "Error".red().bold());
                std::process::exit(1);
            }

            println!("✨ Archivo restaurado: {} ({} bytes)", payload.filename.yellow(), payload.file_data.len());
            println!("💾 Guardado en: {}", target_path.display().to_string().bright_green().bold());
            println!("{}", "✅ Descifrado verificado y completado.".bright_green().bold());
        }

        Commands::Test => {
            println!("{}", "🧪  EJECUTANDO KNOWN ANSWER TESTS (KAT) — PROJECT MIRAGE".bright_cyan().bold());
            println!("{}", "========================================================".dimmed());
            let summary = run_known_answer_tests();
            for t in &summary.tests {
                if t.passed {
                    println!("  {} {} {}", "PASS".green().bold(), t.name.white(), format!("({})", t.source).dimmed());
                } else {
                    println!("  {} {} {}", "FAIL".red().bold(), t.name.white(), format!("{:?}", t.detail).red());
                }
            }
            println!("{}", "--------------------------------------------------------".dimmed());
            if summary.overall {
                println!("{}", "🎉 Todos los vectores de referencia coinciden con los estándares publicados.".bright_green().bold());
            } else {
                println!("{}", "❌ Algunos vectores fallaron.".red().bold());
                std::process::exit(1);
            }
        }

        Commands::Split {
            file,
            threshold,
            total,
        } => {
            println!("🧩 Fragmentando {:?} (umbral: {threshold}/{total})...", file);
            let bytes = fs::read(&file).unwrap();
            let shares = split_secret(&bytes, threshold, total).unwrap();
            let stem = file.file_stem().unwrap().to_str().unwrap();
            for (i, share) in shares.iter().enumerate() {
                let share_path = PathBuf::from(format!("{stem}.part{}.share", i + 1));
                fs::write(&share_path, share).unwrap();
                println!("  Guardado: {:?}", share_path);
            }
        }

        Commands::Combine { shares, output } => {
            println!("🧩 Recombinando {} fragmentos...", shares.len());
            let mut share_buffers = Vec::new();
            for s in &shares {
                share_buffers.push(fs::read(s).unwrap());
            }
            let slices: Vec<&[u8]> = share_buffers.iter().map(|b| b.as_slice()).collect();
            let secret = combine_shares(&slices).unwrap();
            fs::write(&output, secret).unwrap();
            println!("✅ Secreto reconstruido en: {:?}", output);
        }
    }
}
