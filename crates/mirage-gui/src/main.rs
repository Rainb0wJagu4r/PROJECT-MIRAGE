use eframe::egui::{self, Align, Color32, FontId, Layout, RichText, Rounding, Stroke, Vec2};
use mirage_core::format::{
    append_to_carrier, deserialize_payload, extract_from_carrier, serialize_payload,
};
use mirage_core::kat::{run_known_answer_tests, KatSummary};
use mirage_core::kdf::assess_password_strength;
use mirage_core::paths::safe_basename;
use mirage_core::shamir::{combine_shares, split_secret};
use mirage_core::vault::{
    decrypt_vault, encrypt_vault, Algorithm, DecryptVaultOptions, EncryptVaultOptions,
};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(PartialEq)]
enum ActiveTab {
    Encrypt,
    Decrypt,
    Shamir,
    Diagnostics,
}

struct MirageApp {
    active_tab: ActiveTab,

    // Encrypt State
    encrypt_file: Option<PathBuf>,
    encrypt_file_size: usize,
    encrypt_file_hash: String,
    encrypt_password: String,
    encrypt_show_password: bool,
    encrypt_2fa: String,
    encrypt_algorithm: Algorithm,
    encrypt_padme: bool,
    encrypt_shamir: bool,
    encrypt_carrier_file: Option<PathBuf>,
    encrypt_duress_enabled: bool,
    encrypt_duress_password: String,
    encrypt_duress_file: Option<PathBuf>,

    // Decrypt State
    decrypt_files: Vec<PathBuf>,
    decrypt_password: String,
    decrypt_show_password: bool,
    decrypt_2fa: String,

    // Shamir Tab State
    shamir_input_file: Option<PathBuf>,
    shamir_threshold: u8,
    shamir_total: u8,

    // Logs & Status
    logs: Vec<(String, Color32)>,
    kat_summary: KatSummary,
}

impl Default for MirageApp {
    fn default() -> Self {
        let kat_summary = run_known_answer_tests();
        Self {
            active_tab: ActiveTab::Encrypt,

            encrypt_file: None,
            encrypt_file_size: 0,
            encrypt_file_hash: String::new(),
            encrypt_password: String::new(),
            encrypt_show_password: false,
            encrypt_2fa: String::new(),
            encrypt_algorithm: Algorithm::CascadeC4,
            encrypt_padme: true,
            encrypt_shamir: false,
            encrypt_carrier_file: None,
            encrypt_duress_enabled: false,
            encrypt_duress_password: String::new(),
            encrypt_duress_file: None,

            decrypt_files: Vec::new(),
            decrypt_password: String::new(),
            decrypt_show_password: false,
            decrypt_2fa: String::new(),

            shamir_input_file: None,
            shamir_threshold: 2,
            shamir_total: 3,

            logs: vec![(
                "🚀 Project Mirage 100% Native Rust Engine Initialized.".into(),
                Color32::from_rgb(0, 240, 255),
            )],
            kat_summary,
        }
    }
}

impl MirageApp {
    fn set_encrypt_file(&mut self, path: PathBuf) {
        if let Ok(bytes) = fs::read(&path) {
            self.encrypt_file_size = bytes.len();
            let mut hasher = Sha3_256::new();
            hasher.update(&bytes);
            self.encrypt_file_hash = hex::encode(hasher.finalize());
            self.encrypt_file = Some(path.clone());
            self.add_log(
                format!(
                    "📁 Archivo seleccionado: {} ({} bytes)",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    bytes.len()
                ),
                Color32::from_rgb(0, 240, 255),
            );
        }
    }

    fn add_log(&mut self, msg: impl Into<String>, color: Color32) {
        self.logs.push((msg.into(), color));
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }
}

impl eframe::App for MirageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply Custom Dark Cyberpunk Style
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(Color32::from_rgb(226, 232, 240));
        visuals.panel_fill = Color32::from_rgb(11, 15, 25);
        visuals.window_fill = Color32::from_rgb(17, 24, 39);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(17, 24, 39);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(30, 41, 59));
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(24, 32, 47);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(51, 65, 85));
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 41, 59);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, Color32::from_rgb(0, 240, 255));
        visuals.widgets.active.bg_fill = Color32::from_rgb(15, 23, 42);
        visuals.widgets.active.bg_stroke = Stroke::new(2.0, Color32::from_rgb(168, 85, 247));
        visuals.widgets.inactive.rounding = Rounding::same(6.0);
        visuals.widgets.hovered.rounding = Rounding::same(6.0);
        visuals.widgets.active.rounding = Rounding::same(6.0);
        ctx.set_visuals(visuals);

        // Header Panel
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🛡️ PROJECT MIRAGE")
                        .font(FontId::proportional(20.0))
                        .color(Color32::from_rgb(0, 240, 255))
                        .strong(),
                );
                ui.label(
                    RichText::new("v2.2.0 (100% Pure Rust Native Engine)")
                        .font(FontId::monospace(12.0))
                        .color(Color32::from_rgb(148, 163, 184)),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.kat_summary.overall {
                        ui.label(
                            RichText::new("● KAT STATUS: ONLINE (AUDITED)")
                                .font(FontId::monospace(11.0))
                                .color(Color32::from_rgb(16, 185, 129))
                                .strong(),
                        );
                    } else {
                        ui.label(
                            RichText::new("▲ KAT STATUS: FAILED")
                                .font(FontId::monospace(11.0))
                                .color(Color32::from_rgb(239, 68, 68))
                                .strong(),
                        );
                    }
                });
            });
            ui.add_space(4.0);

            // Tab Navigation Bar
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.active_tab == ActiveTab::Encrypt, "  🔒 CIFRAR & ARMAR  ")
                    .clicked()
                {
                    self.active_tab = ActiveTab::Encrypt;
                }
                if ui
                    .selectable_label(
                        self.active_tab == ActiveTab::Decrypt,
                        "  🔓 DESCIFRAR & RESTAURAR  ",
                    )
                    .clicked()
                {
                    self.active_tab = ActiveTab::Decrypt;
                }
                if ui
                    .selectable_label(self.active_tab == ActiveTab::Shamir, "  🧩 SHAMIR 2-DE-3  ")
                    .clicked()
                {
                    self.active_tab = ActiveTab::Shamir;
                }
                if ui
                    .selectable_label(
                        self.active_tab == ActiveTab::Diagnostics,
                        "  🧪 DIAGNÓSTICO & KATS  ",
                    )
                    .clicked()
                {
                    self.active_tab = ActiveTab::Diagnostics;
                }
            });
            ui.add_space(6.0);
        });

        // Bottom Status / Log Bar
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("TERMINAL LOG:")
                        .font(FontId::monospace(11.0))
                        .color(Color32::from_rgb(148, 163, 184)),
                );
                if let Some((msg, color)) = self.logs.last() {
                    ui.label(RichText::new(msg).font(FontId::monospace(11.0)).color(*color));
                }
            });
            ui.add_space(4.0);
        });

        // Main Central Content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(10.0);

                match self.active_tab {
                    ActiveTab::Encrypt => self.render_encrypt_tab(ui),
                    ActiveTab::Decrypt => self.render_decrypt_tab(ui),
                    ActiveTab::Shamir => self.render_shamir_tab(ui),
                    ActiveTab::Diagnostics => self.render_diagnostics_tab(ui),
                }

                ui.add_space(20.0);
            });
        });
    }
}

impl MirageApp {
    fn render_encrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("1. ARCHIVO DE ENTRADA")
                        .font(FontId::proportional(14.0))
                        .color(Color32::from_rgb(0, 240, 255))
                        .strong(),
                );
            });
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                if ui.button(" 📂 Seleccionar Archivo... ").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.set_encrypt_file(path);
                    }
                }

                if let Some(file) = &self.encrypt_file {
                    ui.label(
                        RichText::new(format!(
                            "{} ({} bytes)",
                            file.file_name().unwrap_or_default().to_string_lossy(),
                            self.encrypt_file_size
                        ))
                        .color(Color32::from_rgb(250, 204, 21)),
                    );
                } else {
                    ui.label(
                        RichText::new("Ningún archivo seleccionado")
                            .color(Color32::from_rgb(100, 116, 139)),
                    );
                }
            });

            if !self.encrypt_file_hash.is_empty() {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("SHA3-256:")
                            .font(FontId::monospace(11.0))
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                    ui.label(
                        RichText::new(&self.encrypt_file_hash)
                            .font(FontId::monospace(11.0))
                            .color(Color32::from_rgb(52, 211, 153)),
                    );
                });
            }
        });

        ui.add_space(10.0);

        // Password & Security
        ui.group(|ui| {
            ui.label(
                RichText::new("2. CLAVES Y POLÍTICA DE SEGURIDAD")
                    .font(FontId::proportional(14.0))
                    .color(Color32::from_rgb(0, 240, 255))
                    .strong(),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("Contraseña Maestra:");
                if self.encrypt_show_password {
                    ui.add(egui::TextEdit::singleline(&mut self.encrypt_password).desired_width(280.0));
                } else {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.encrypt_password)
                            .password(true)
                            .desired_width(280.0),
                    );
                }
                if ui
                    .button(if self.encrypt_show_password { "👁️ Ocultar" } else { "👁️ Ver" })
                    .clicked()
                {
                    self.encrypt_show_password = !self.encrypt_show_password;
                }
            });

            // Entropy Meter
            if !self.encrypt_password.is_empty() {
                let assessment = assess_password_strength(&self.encrypt_password);
                ui.horizontal(|ui| {
                    match assessment {
                        Ok(bits) => {
                            ui.label(
                                RichText::new(format!("● Fortaleza: Excelente (~{} bits de entropía)", bits))
                                    .color(Color32::from_rgb(16, 185, 129))
                                    .font(FontId::monospace(11.0)),
                            );
                        }
                        Err(reason) => {
                            ui.label(
                                RichText::new(format!("▲ No recomendada: {}", reason))
                                    .color(Color32::from_rgb(239, 68, 68))
                                    .font(FontId::monospace(11.0)),
                            );
                        }
                    }
                });
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("2FA Simétrico (Opcional):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.encrypt_2fa)
                        .password(true)
                        .desired_width(280.0),
                );
            });
        });

        ui.add_space(10.0);

        // Cryptographic Suite & Options
        ui.group(|ui| {
            ui.label(
                RichText::new("3. ESPECIFICACIÓN Y ALGORITMOS")
                    .font(FontId::proportional(14.0))
                    .color(Color32::from_rgb(0, 240, 255))
                    .strong(),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("Algoritmo de cifrado:");
                egui::ComboBox::from_id_salt("algo_select")
                    .selected_text(match self.encrypt_algorithm {
                        Algorithm::CascadeC4 => "Mirage-C4 v2 (Camellia-CBC + ChaCha20 + ARIA-CBC + AES-GCM)",
                        Algorithm::AesGcm => "AES-256-GCM (Estándar Único)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.encrypt_algorithm,
                            Algorithm::CascadeC4,
                            "Mirage-C4 v2 (Camellia-CBC + ChaCha20 + ARIA-CBC + AES-GCM)",
                        );
                        ui.selectable_value(
                            &mut self.encrypt_algorithm,
                            Algorithm::AesGcm,
                            "AES-256-GCM (Estándar Único)",
                        );
                    });
            });

            ui.add_space(6.0);
            ui.checkbox(
                &mut self.encrypt_padme,
                "Ocultación de tamaño por cuantización Padmé (Signal/PURBs PETS 2019)",
            );
            ui.checkbox(
                &mut self.encrypt_shamir,
                "Dividir en fragmentos 2-de-3 (Shamir Secret Sharing sobre GF(256))",
            );

            // Steganography Option
            ui.horizontal(|ui| {
                if ui.button("🖼️ Ocultar en Imagen Portadora...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Imágenes", &["png", "jpg", "jpeg"])
                        .pick_file()
                    {
                        self.encrypt_carrier_file = Some(path);
                    }
                }
                if let Some(c) = &self.encrypt_carrier_file {
                    ui.label(
                        RichText::new(c.file_name().unwrap_or_default().to_string_lossy())
                            .color(Color32::from_rgb(168, 85, 247)),
                    );
                    if ui.button("✖").clicked() {
                        self.encrypt_carrier_file = None;
                    }
                }
            });

            // Duress Mode Toggle
            ui.checkbox(&mut self.encrypt_duress_enabled, "Modo de Coacción (Duress Mode con documento señuelo)");
            if self.encrypt_duress_enabled {
                ui.indent("duress_indent", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Contraseña Señuelo:");
                        ui.add(egui::TextEdit::singleline(&mut self.encrypt_duress_password).password(true));
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Seleccionar Archivo Señuelo...").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.encrypt_duress_file = Some(path);
                            }
                        }
                        if let Some(df) = &self.encrypt_duress_file {
                            ui.label(df.file_name().unwrap_or_default().to_string_lossy());
                        }
                    });
                });
            }
        });

        ui.add_space(15.0);

        // Action Button
        let can_encrypt = self.encrypt_file.is_some() && !self.encrypt_password.is_empty();
        ui.add_enabled_ui(can_encrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  ⚡ CIFRAR Y ARMAR CONTENEDOR .WRAITH  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::BLACK)
                    .strong(),
            )
            .fill(Color32::from_rgb(0, 240, 255))
            .min_size(Vec2::new(ui.available_width(), 44.0));

            if ui.add(btn).clicked() {
                self.perform_encryption();
            }
        });
    }

    fn perform_encryption(&mut self) {
        let Some(file_path) = self.encrypt_file.clone() else { return };
        let Ok(file_bytes) = fs::read(&file_path) else {
            self.add_log("Error al leer el archivo de origen.", Color32::RED);
            return;
        };

        let start = Instant::now();
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();

        let Ok(payload) = serialize_payload(&filename, &file_bytes, 0) else {
            self.add_log("Error al serializar el payload.", Color32::RED);
            return;
        };

        let mut decoy_payload = None;
        if self.encrypt_duress_enabled {
            if let Some(df) = &self.encrypt_duress_file {
                if let Ok(df_bytes) = fs::read(df) {
                    let df_name = df.file_name().unwrap_or_default().to_string_lossy();
                    decoy_payload = serialize_payload(&df_name, &df_bytes, 0).ok();
                }
            }
        }

        let sf_opt = if self.encrypt_2fa.is_empty() { None } else { Some(self.encrypt_2fa.as_str()) };
        let duress_pw_opt = if self.encrypt_duress_enabled { Some(self.encrypt_duress_password.as_str()) } else { None };

        let enc_res = match encrypt_vault(EncryptVaultOptions {
            payload: &payload,
            decoy_payload: decoy_payload.as_deref(),
            password: &self.encrypt_password,
            second_factor: sf_opt,
            duress_password: duress_pw_opt,
            hardware_id: None,
            algorithm: self.encrypt_algorithm,
            bucket_padding: self.encrypt_padme,
            is_vault: false,
        }) {
            Ok(res) => res,
            Err(e) => {
                self.add_log(format!("Fallo de cifrado: {}", e.public_message()), Color32::RED);
                return;
            }
        };

        let mut final_data = enc_res.envelope;

        if let Some(c_path) = &self.encrypt_carrier_file {
            if let Ok(c_bytes) = fs::read(c_path) {
                final_data = append_to_carrier(&c_bytes, &final_data);
            }
        }

        if self.encrypt_shamir {
            let shares = split_secret(&final_data, 2, 3).unwrap();
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            let parent = file_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            for (i, share) in shares.iter().enumerate() {
                let share_path = parent.join(format!("{stem}.part{}.share", i + 1));
                fs::write(&share_path, share).unwrap();
                self.add_log(format!("✨ Fragmento guardado: {:?}", share_path), Color32::from_rgb(16, 185, 129));
            }
        } else {
            let out_path = file_path.with_extension("wraith");
            if let Err(e) = fs::write(&out_path, &final_data) {
                self.add_log(format!("Error al escribir archivo: {e}"), Color32::RED);
                return;
            }
            self.add_log(
                format!("💾 Contenedor cifrado guardado en: {:?} ({:.2} ms)", out_path, start.elapsed().as_secs_f64() * 1000.0),
                Color32::from_rgb(16, 185, 129),
            );
        }
    }

    fn render_decrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(
                RichText::new("1. SELECCIONAR CONTENEDOR O FRAGMENTOS")
                    .font(FontId::proportional(14.0))
                    .color(Color32::from_rgb(0, 240, 255))
                    .strong(),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                if ui.button(" 📂 Seleccionar Archivo (.wraith / .share)... ").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        self.decrypt_files = files;
                    }
                }

                if !self.decrypt_files.is_empty() {
                    ui.label(
                        RichText::new(format!("{} archivo(s) seleccionado(s)", self.decrypt_files.len()))
                            .color(Color32::from_rgb(250, 204, 21)),
                    );
                }
            });

            for f in &self.decrypt_files {
                ui.label(RichText::new(format!("  • {:?}", f.file_name().unwrap_or_default())).font(FontId::monospace(11.0)));
            }
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label(
                RichText::new("2. CREDENCIALES DE DESCIFRADO")
                    .font(FontId::proportional(14.0))
                    .color(Color32::from_rgb(0, 240, 255))
                    .strong(),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("Contraseña:");
                if self.decrypt_show_password {
                    ui.add(egui::TextEdit::singleline(&mut self.decrypt_password).desired_width(280.0));
                } else {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.decrypt_password)
                            .password(true)
                            .desired_width(280.0),
                    );
                }
                if ui.button(if self.decrypt_show_password { "👁️ Ocultar" } else { "👁️ Ver" }).clicked() {
                    self.decrypt_show_password = !self.decrypt_show_password;
                }
            });

            ui.horizontal(|ui| {
                ui.label("Segundo Factor 2FA (si fue requerido):");
                ui.add(egui::TextEdit::singleline(&mut self.decrypt_2fa).password(true).desired_width(280.0));
            });
        });

        ui.add_space(15.0);

        let can_decrypt = !self.decrypt_files.is_empty() && !self.decrypt_password.is_empty();
        ui.add_enabled_ui(can_decrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  🔓 DESCIFRAR Y RESTAURAR ARCHIVO  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::BLACK)
                    .strong(),
            )
            .fill(Color32::from_rgb(16, 185, 129))
            .min_size(Vec2::new(ui.available_width(), 44.0));

            if ui.add(btn).clicked() {
                self.perform_decryption();
            }
        });
    }

    fn perform_decryption(&mut self) {
        let raw_data = if self.decrypt_files.len() > 1 || self.decrypt_files[0].extension().map_or(false, |ext| ext == "share") {
            let mut share_buffers = Vec::new();
            for f in &self.decrypt_files {
                if let Ok(b) = fs::read(f) {
                    share_buffers.push(b);
                }
            }
            let slices: Vec<&[u8]> = share_buffers.iter().map(|b| b.as_slice()).collect();
            match combine_shares(&slices) {
                Ok(d) => d,
                Err(e) => {
                    self.add_log(format!("Error al recombinar fragmentos: {}", e.public_message()), Color32::RED);
                    return;
                }
            }
        } else {
            match fs::read(&self.decrypt_files[0]) {
                Ok(d) => d,
                Err(e) => {
                    self.add_log(format!("Error al leer archivo: {e}"), Color32::RED);
                    return;
                }
            }
        };

        let (envelope, was_steg) = extract_from_carrier(&raw_data).unwrap_or((raw_data, false));
        if was_steg {
            self.add_log("🖼️ Envoltorio esteganográfico extraído de imagen portadora.", Color32::from_rgb(168, 85, 247));
        }

        let sf_opt = if self.decrypt_2fa.is_empty() { None } else { Some(self.decrypt_2fa.as_str()) };

        let dec = match decrypt_vault(
            &envelope,
            DecryptVaultOptions {
                password: &self.decrypt_password,
                second_factor: sf_opt,
                hardware_id: None,
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                self.add_log(format!("Fallo de autenticación: {}", e.public_message()), Color32::RED);
                return;
            }
        };

        if dec.is_duress {
            self.add_log("⚠️ AVISO: Contenido señuelo restaurado (modo de coacción).", Color32::from_rgb(250, 204, 21));
        }

        let Ok(payload) = deserialize_payload(&dec.payload) else {
            self.add_log("Error al deserializar payload interno.", Color32::RED);
            return;
        };

        let safe_name = safe_basename(&payload.filename, "restored.bin");
        let parent = self.decrypt_files[0].parent().unwrap_or_else(|| std::path::Path::new("."));
        let target_path = parent.join(format!("restored_{safe_name}"));

        if let Err(e) = fs::write(&target_path, &payload.file_data) {
            self.add_log(format!("Error al guardar archivo restaurado: {e}"), Color32::RED);
            return;
        }

        self.add_log(
            format!("✅ Archivo restaurado con éxito en: {:?} ({} bytes)", target_path, payload.file_data.len()),
            Color32::from_rgb(16, 185, 129),
        );
    }

    fn render_shamir_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("FRAGMENTACIÓN 2-DE-3 (SHAMIR SECRET SHARING)").font(FontId::proportional(14.0)).color(Color32::from_rgb(0, 240, 255)).strong());
            ui.add_space(6.0);
            ui.label("Divide cualquier archivo en partes donde K fragmentos cualesquiera reconstruyen el original y K-1 no revelan absolutamente nada.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if ui.button(" 📂 Seleccionar Archivo a Fragmentar... ").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.shamir_input_file = Some(path);
                    }
                }
                if let Some(f) = &self.shamir_input_file {
                    ui.label(f.file_name().unwrap_or_default().to_string_lossy());
                }
            });

            ui.add_space(6.0);
            ui.add(egui::Slider::new(&mut self.shamir_threshold, 2..=5).text("Umbral de Reconstrucción (K)"));
            ui.add(egui::Slider::new(&mut self.shamir_total, 2..=10).text("Total de Fragmentos Generados (N)"));

            ui.add_space(8.0);
            if ui.button(" 🧩 Fragmentar Archivo ").clicked() {
                if let Some(path) = self.shamir_input_file.clone() {
                    if let Ok(bytes) = fs::read(&path) {
                        if let Ok(shares) = split_secret(&bytes, self.shamir_threshold, self.shamir_total) {
                            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                            let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                            for (i, s) in shares.iter().enumerate() {
                                let sp = parent.join(format!("{stem}.part{}.share", i + 1));
                                fs::write(&sp, s).unwrap();
                                self.add_log(format!("Fragmento guardado: {:?}", sp), Color32::from_rgb(16, 185, 129));
                            }
                        }
                    }
                }
            }
        });
    }

    fn render_diagnostics_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(RichText::new("KNOWN ANSWER TESTS (KAT) — AUDITORÍA EN TIEMPO REAL").font(FontId::proportional(14.0)).color(Color32::from_rgb(0, 240, 255)).strong());
            ui.add_space(6.0);
            ui.label(&self.kat_summary.disclaimer);
            ui.add_space(10.0);

            for test in &self.kat_summary.tests {
                ui.horizontal(|ui| {
                    if test.passed {
                        ui.label(RichText::new(" PASS ").color(Color32::BLACK).background_color(Color32::from_rgb(16, 185, 129)).strong());
                    } else {
                        ui.label(RichText::new(" FAIL ").color(Color32::WHITE).background_color(Color32::from_rgb(239, 68, 68)).strong());
                    }
                    ui.label(RichText::new(&test.name).strong());
                    ui.label(RichText::new(format!("({})", test.source)).color(Color32::from_rgb(148, 163, 184)));
                });
                ui.add_space(2.0);
            }

            ui.add_space(10.0);
            if ui.button(" 🔄 Re-ejecutar Diagnóstico ").clicked() {
                self.kat_summary = run_known_answer_tests();
                self.add_log("Diagnóstico KAT re-ejecutado.", Color32::from_rgb(0, 240, 255));
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Project Mirage — Cryptographic Vault (Pure Rust)")
            .with_inner_size([760.0, 680.0])
            .with_min_inner_size([600.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Project Mirage",
        native_options,
        Box::new(|_cc| Ok(Box::new(MirageApp::default()))),
    )
}
