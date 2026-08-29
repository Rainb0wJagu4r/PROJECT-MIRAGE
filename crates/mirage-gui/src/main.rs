use eframe::egui::{
    self, Align, Color32, FontId, Frame, Layout, Margin, RichText, Rounding, Stroke, Vec2,
};
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

// Custom Theme Colors (Cyberpunk Dark Obsidian & Neon Accents)
const BG_DARK_OBSIDIAN: Color32 = Color32::from_rgb(10, 13, 20);
const BG_CARD: Color32 = Color32::from_rgb(17, 23, 36);
const BG_CARD_HOVER: Color32 = Color32::from_rgb(23, 31, 48);
const BG_INPUT: Color32 = Color32::from_rgb(12, 17, 27);

const NEON_CYAN: Color32 = Color32::from_rgb(0, 240, 255);
const NEON_PURPLE: Color32 = Color32::from_rgb(168, 85, 247);
const NEON_EMERALD: Color32 = Color32::from_rgb(16, 185, 129);
const NEON_AMBER: Color32 = Color32::from_rgb(245, 158, 11);
const NEON_ROSE: Color32 = Color32::from_rgb(244, 63, 94);

const TEXT_PRIMARY: Color32 = Color32::from_rgb(241, 245, 249);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(148, 163, 184);
const TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139);
const BORDER_SUBTLE: Color32 = Color32::from_rgb(30, 41, 59);

#[derive(PartialEq, Clone, Copy)]
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
    last_action_banner: Option<(String, bool)>,
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
                "⚡ Project Mirage v2.2.0 Core Initialized [Memory-Safe Rust Engine]".into(),
                NEON_CYAN,
            )],
            kat_summary,
            last_action_banner: None,
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
                    "📁 Archivo cargado: {} ({})",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    format_bytes(bytes.len())
                ),
                NEON_CYAN,
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

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn card_frame() -> Frame {
    Frame::none()
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::same(14.0))
}

fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str, accent: Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).font(FontId::proportional(14.0)).color(accent).strong());
        if !subtitle.is_empty() {
            ui.label(RichText::new(format!("— {subtitle}")).font(FontId::proportional(12.0)).color(TEXT_MUTED));
        }
    });
    ui.add_space(8.0);
}

impl eframe::App for MirageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Configure Custom Theme Visuals
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_DARK_OBSIDIAN;
        visuals.window_fill = BG_DARK_OBSIDIAN;
        visuals.extreme_bg_color = BG_INPUT;
        visuals.override_text_color = Some(TEXT_PRIMARY);

        visuals.widgets.noninteractive.bg_fill = BG_CARD;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
        visuals.widgets.noninteractive.rounding = Rounding::same(8.0);

        visuals.widgets.inactive.bg_fill = Color32::from_rgb(20, 28, 44);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
        visuals.widgets.inactive.rounding = Rounding::same(8.0);

        visuals.widgets.hovered.bg_fill = BG_CARD_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, NEON_CYAN);
        visuals.widgets.hovered.rounding = Rounding::same(8.0);

        visuals.widgets.active.bg_fill = Color32::from_rgb(14, 20, 32);
        visuals.widgets.active.bg_stroke = Stroke::new(2.0, NEON_PURPLE);
        visuals.widgets.active.rounding = Rounding::same(8.0);

        visuals.selection.bg_fill = Color32::from_rgb(0, 240, 255).linear_multiply(0.25);
        visuals.selection.stroke = Stroke::new(1.5, NEON_CYAN);

        ctx.set_visuals(visuals);

        // Header Top Bar
        egui::TopBottomPanel::top("top_header")
            .frame(Frame::none().fill(BG_DARK_OBSIDIAN).inner_margin(Margin::symmetric(20.0, 14.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("PROJECT MIRAGE")
                            .font(FontId::proportional(22.0))
                            .color(NEON_CYAN)
                            .strong(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(" // ARMORED CRYPTOSYSTEM")
                            .font(FontId::monospace(12.0))
                            .color(TEXT_SECONDARY),
                    );

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        // Badge KAT Status
                        let (badge_text, badge_color, border_color) = if self.kat_summary.overall {
                            ("  ● KAT: 100% ONLINE (AUDITED)  ", NEON_EMERALD, Color32::from_rgb(6, 78, 59))
                        } else {
                            ("  ▲ KAT: INTEGRITY FAILED  ", NEON_ROSE, Color32::from_rgb(136, 19, 55))
                        };

                        Frame::none()
                            .fill(border_color)
                            .stroke(Stroke::new(1.0, badge_color))
                            .rounding(Rounding::same(6.0))
                            .inner_margin(Margin::symmetric(6.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(badge_text).font(FontId::monospace(11.0)).color(badge_color).strong());
                            });
                    });
                });

                ui.add_space(10.0);

                // Modern Pill Segmented Navigation Tab Bar
                ui.horizontal(|ui| {
                    let tabs = [
                        (ActiveTab::Encrypt, " 🔒 Cifrar & Armar "),
                        (ActiveTab::Decrypt, " 🔓 Descifrar & Restaurar "),
                        (ActiveTab::Shamir, " 🧩 Shamir 2-de-3 "),
                        (ActiveTab::Diagnostics, " 🧪 Diagnóstico & KATs "),
                    ];

                    for (tab_type, title) in tabs {
                        let is_active = self.active_tab == tab_type;
                        let bg_color = if is_active { NEON_CYAN } else { Color32::from_rgb(20, 28, 44) };
                        let text_color = if is_active { Color32::BLACK } else { TEXT_PRIMARY };
                        let stroke = if is_active { Stroke::new(1.5, NEON_CYAN) } else { Stroke::new(1.0, BORDER_SUBTLE) };

                        let btn = egui::Button::new(
                            RichText::new(title)
                                .font(FontId::proportional(13.0))
                                .color(text_color)
                                .strong(),
                        )
                        .fill(bg_color)
                        .stroke(stroke)
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(140.0, 32.0));

                        if ui.add(btn).clicked() {
                            self.active_tab = tab_type;
                        }
                        ui.add_space(4.0);
                    }
                });
            });

        // Bottom Status / Console Log Bar
        egui::TopBottomPanel::bottom("bottom_bar")
            .frame(Frame::none().fill(BG_CARD).inner_margin(Margin::symmetric(16.0, 8.0)).stroke(Stroke::new(1.0, BORDER_SUBTLE)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("TERMINAL:").font(FontId::monospace(11.0)).color(TEXT_MUTED).strong());
                    if let Some((msg, color)) = self.logs.last() {
                        ui.label(RichText::new(msg).font(FontId::monospace(11.0)).color(*color));
                    }
                });
            });

        // Central Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(8.0);

                if let Some((msg, success)) = &self.last_action_banner {
                    let (bg, border, fg) = if *success {
                        (Color32::from_rgb(6, 78, 59), NEON_EMERALD, Color32::WHITE)
                    } else {
                        (Color32::from_rgb(136, 19, 55), NEON_ROSE, Color32::WHITE)
                    };
                    Frame::none()
                        .fill(bg)
                        .stroke(Stroke::new(1.0, border))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(14.0, 10.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(msg).font(FontId::proportional(13.0)).color(fg).strong());
                        });
                    ui.add_space(8.0);
                }

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
        // 1. File Selector Card
        card_frame().show(ui, |ui| {
            section_title(ui, "1. ARCHIVO DE ORIGEN", "Selecciona el archivo confidencial a proteger", NEON_CYAN);

            ui.horizontal(|ui| {
                let pick_btn = egui::Button::new(
                    RichText::new(" 📂 Explorar Archivo... ")
                        .font(FontId::proportional(13.0))
                        .color(TEXT_PRIMARY)
                        .strong(),
                )
                .fill(Color32::from_rgb(26, 36, 56))
                .stroke(Stroke::new(1.0, NEON_CYAN))
                .min_size(Vec2::new(160.0, 36.0));

                if ui.add(pick_btn).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.set_encrypt_file(path);
                    }
                }

                ui.add_space(10.0);

                if let Some(file) = &self.encrypt_file {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!("✔ {}", file.file_name().unwrap_or_default().to_string_lossy()))
                                .font(FontId::proportional(14.0))
                                .color(NEON_EMERALD)
                                .strong(),
                        );
                        ui.label(
                            RichText::new(format!("Tamaño: {}", format_bytes(self.encrypt_file_size)))
                                .font(FontId::proportional(12.0))
                                .color(TEXT_SECONDARY),
                        );
                    });
                } else {
                    ui.label(
                        RichText::new("Arrastra o selecciona un archivo para comenzar...")
                            .font(FontId::proportional(13.0))
                            .color(TEXT_MUTED),
                    );
                }
            });

            if !self.encrypt_file_hash.is_empty() {
                ui.add_space(8.0);
                Frame::none()
                    .fill(BG_INPUT)
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(10.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("SHA3-256 HASH:").font(FontId::monospace(10.0)).color(TEXT_MUTED).strong());
                            ui.label(RichText::new(&self.encrypt_file_hash).font(FontId::monospace(10.0)).color(NEON_CYAN));
                        });
                    });
            }
        });

        ui.add_space(12.0);

        // 2. Cryptographic Credentials & Entropy
        card_frame().show(ui, |ui| {
            section_title(ui, "2. AUTENTICACIÓN & ENTROPÍA", "Clave maestra blindada con Scrypt (N=131072, r=8, p=1)", NEON_CYAN);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Contraseña Maestra:").font(FontId::proportional(13.0)).color(TEXT_SECONDARY));
                let mut edit = egui::TextEdit::singleline(&mut self.encrypt_password)
                    .desired_width(320.0)
                    .margin(Margin::symmetric(8.0, 6.0));
                if !self.encrypt_show_password {
                    edit = edit.password(true);
                }
                ui.add(edit);

                if ui.button(if self.encrypt_show_password { "👁️ Ocultar" } else { "👁️ Ver" }).clicked() {
                    self.encrypt_show_password = !self.encrypt_show_password;
                }
            });

            // Entropy Gauge
            if !self.encrypt_password.is_empty() {
                ui.add_space(6.0);
                let assessment = assess_password_strength(&self.encrypt_password);
                let (bits_label, color, fill_pct) = match assessment {
                    Ok(bits) => {
                        let pct = ((bits as f32) / 100.0).clamp(0.0, 1.0);
                        (format!("● Fortaleza Alta: ~{bits} bits de entropía (Cumple Política de Seguridad)"), NEON_EMERALD, pct)
                    }
                    Err(err) => {
                        (format!("▲ Atención: {err}"), NEON_ROSE, 0.25)
                    }
                };

                ui.label(RichText::new(bits_label).font(FontId::monospace(11.0)).color(color).strong());
                ui.add_space(2.0);
                let progress_bar = egui::ProgressBar::new(fill_pct)
                    .fill(color)
                    .animate(false);
                ui.add(progress_bar);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("2FA Simétrico (Opcional):").font(FontId::proportional(13.0)).color(TEXT_SECONDARY));
                ui.add(
                    egui::TextEdit::singleline(&mut self.encrypt_2fa)
                        .password(true)
                        .desired_width(320.0)
                        .margin(Margin::symmetric(8.0, 6.0)),
                );
            });
        });

        ui.add_space(12.0);

        // 3. Cryptographic Suite & Security Options
        card_frame().show(ui, |ui| {
            section_title(ui, "3. SUITE CRIPTOGRÁFICA & PROTECCIONES", "Parámetros avanzados del contenedor .wraith", NEON_CYAN);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Algoritmo de cifrado:").font(FontId::proportional(13.0)).color(TEXT_SECONDARY));
                egui::ComboBox::from_id_salt("algo_picker")
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

            ui.add_space(8.0);
            ui.checkbox(&mut self.encrypt_padme, RichText::new("Ocultación de longitud Padmé (Cuantización con sobrecoste ≤ 12% - PETS 2019)").font(FontId::proportional(13.0)));
            ui.checkbox(&mut self.encrypt_shamir, RichText::new("Dividir en fragmentos 2-de-3 (Shamir Secret Sharing con HMAC sobre GF(256))").font(FontId::proportional(13.0)));

            ui.add_space(6.0);
            // Steganography Carrier Selector
            ui.horizontal(|ui| {
                let steg_btn = egui::Button::new(
                    RichText::new(" 🖼️ Ocultar en Imagen Portadora (Esteganografía)... ")
                        .font(FontId::proportional(12.0)),
                );
                if ui.add(steg_btn).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Imágenes", &["png", "jpg", "jpeg"])
                        .pick_file()
                    {
                        self.encrypt_carrier_file = Some(path);
                    }
                }
                if let Some(c) = &self.encrypt_carrier_file {
                    ui.label(RichText::new(c.file_name().unwrap_or_default().to_string_lossy()).color(NEON_PURPLE).strong());
                    if ui.button("✖").clicked() {
                        self.encrypt_carrier_file = None;
                    }
                }
            });

            ui.add_space(6.0);
            // Duress Mode Options
            ui.checkbox(&mut self.encrypt_duress_enabled, RichText::new("Modo de Coacción (Duress Mode con documento señuelo)").font(FontId::proportional(13.0)));
            if self.encrypt_duress_enabled {
                Frame::none()
                    .fill(Color32::from_rgb(26, 20, 36))
                    .stroke(Stroke::new(1.0, NEON_PURPLE))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Contraseña Señuelo:");
                            ui.add(egui::TextEdit::singleline(&mut self.encrypt_duress_password).password(true));
                        });
                        ui.add_space(4.0);
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

        ui.add_space(16.0);

        // Huge Neon Action Button
        let can_encrypt = self.encrypt_file.is_some() && !self.encrypt_password.is_empty();
        ui.add_enabled_ui(can_encrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  ⚡ CIFRAR Y ARMAR CONTENEDOR .WRAITH  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::BLACK)
                    .strong(),
            )
            .fill(NEON_CYAN)
            .rounding(Rounding::same(10.0))
            .min_size(Vec2::new(ui.available_width(), 48.0));

            if ui.add(btn).clicked() {
                self.perform_encryption();
            }
        });
    }

    fn perform_encryption(&mut self) {
        let Some(file_path) = self.encrypt_file.clone() else { return };
        let Ok(file_bytes) = fs::read(&file_path) else {
            self.add_log("Error al leer el archivo de origen.", NEON_ROSE);
            self.last_action_banner = Some(("Error al leer el archivo de origen.".into(), false));
            return;
        };

        let start = Instant::now();
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();

        let Ok(payload) = serialize_payload(&filename, &file_bytes, 0) else {
            self.add_log("Error al serializar el payload.", NEON_ROSE);
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
                let err_msg = e.public_message();
                self.add_log(format!("Fallo de cifrado: {}", err_msg), NEON_ROSE);
                self.last_action_banner = Some((format!("Fallo de cifrado: {err_msg}"), false));
                return;
            }
        };

        let mut final_data = enc_res.envelope;

        if let Some(c_path) = &self.encrypt_carrier_file {
            if let Ok(c_bytes) = fs::read(c_path) {
                final_data = append_to_carrier(&c_bytes, &final_data);
            }
        }

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        if self.encrypt_shamir {
            let shares = split_secret(&final_data, 2, 3).unwrap();
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            let parent = file_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            for (i, share) in shares.iter().enumerate() {
                let share_path = parent.join(format!("{stem}.part{}.share", i + 1));
                fs::write(&share_path, share).unwrap();
                self.add_log(format!("✨ Fragmento guardado: {:?}", share_path), NEON_EMERALD);
            }
            self.last_action_banner = Some((format!("✔ Cifrado y fragmentación 2-de-3 completada exitosamente ({elapsed_ms:.1} ms)"), true));
        } else {
            let out_path = file_path.with_extension("wraith");
            if let Err(e) = fs::write(&out_path, &final_data) {
                self.add_log(format!("Error al escribir archivo: {e}"), NEON_ROSE);
                self.last_action_banner = Some((format!("Error al escribir archivo: {e}"), false));
                return;
            }
            self.add_log(
                format!("💾 Contenedor guardado: {:?} ({elapsed_ms:.1} ms)", out_path),
                NEON_EMERALD,
            );
            self.last_action_banner = Some((format!("✔ Contenedor .wraith cifrado exitosamente en {:?} ({elapsed_ms:.1} ms)", out_path.file_name().unwrap_or_default()), true));
        }
    }

    fn render_decrypt_tab(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "1. SELECCIONAR CONTENEDOR O FRAGMENTOS", "Archivos .wraith o múltiples fragmentos .share", NEON_CYAN);

            ui.horizontal(|ui| {
                let pick_btn = egui::Button::new(
                    RichText::new(" 📂 Seleccionar Archivos... ")
                        .font(FontId::proportional(13.0))
                        .color(TEXT_PRIMARY)
                        .strong(),
                )
                .fill(Color32::from_rgb(26, 36, 56))
                .stroke(Stroke::new(1.0, NEON_CYAN))
                .min_size(Vec2::new(160.0, 36.0));

                if ui.add(pick_btn).clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        self.decrypt_files = files;
                    }
                }

                if !self.decrypt_files.is_empty() {
                    ui.label(
                        RichText::new(format!("✔ {} archivo(s) seleccionado(s)", self.decrypt_files.len()))
                            .font(FontId::proportional(13.0))
                            .color(NEON_EMERALD)
                            .strong(),
                    );
                }
            });

            for f in &self.decrypt_files {
                ui.label(RichText::new(format!("  • {:?}", f.file_name().unwrap_or_default())).font(FontId::monospace(11.0)).color(TEXT_SECONDARY));
            }
        });

        ui.add_space(12.0);

        card_frame().show(ui, |ui| {
            section_title(ui, "2. CREDENCIALES DE APERTURA", "La autenticación AEAD verifica la clave antes de restaurar", NEON_CYAN);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Contraseña:").font(FontId::proportional(13.0)).color(TEXT_SECONDARY));
                let mut edit = egui::TextEdit::singleline(&mut self.decrypt_password)
                    .desired_width(320.0)
                    .margin(Margin::symmetric(8.0, 6.0));
                if !self.decrypt_show_password {
                    edit = edit.password(true);
                }
                ui.add(edit);

                if ui.button(if self.decrypt_show_password { "👁️ Ocultar" } else { "👁️ Ver" }).clicked() {
                    self.decrypt_show_password = !self.decrypt_show_password;
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Segundo Factor 2FA (si aplica):").font(FontId::proportional(13.0)).color(TEXT_SECONDARY));
                ui.add(
                    egui::TextEdit::singleline(&mut self.decrypt_2fa)
                        .password(true)
                        .desired_width(320.0)
                        .margin(Margin::symmetric(8.0, 6.0)),
                );
            });
        });

        ui.add_space(16.0);

        let can_decrypt = !self.decrypt_files.is_empty() && !self.decrypt_password.is_empty();
        ui.add_enabled_ui(can_decrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  🔓 DESCIFRAR Y RESTAURAR ARCHIVO  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::BLACK)
                    .strong(),
            )
            .fill(NEON_EMERALD)
            .rounding(Rounding::same(10.0))
            .min_size(Vec2::new(ui.available_width(), 48.0));

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
                    let err_msg = e.public_message();
                    self.add_log(format!("Error en fragmentos: {}", err_msg), NEON_ROSE);
                    self.last_action_banner = Some((format!("Error en fragmentos: {err_msg}"), false));
                    return;
                }
            }
        } else {
            match fs::read(&self.decrypt_files[0]) {
                Ok(d) => d,
                Err(e) => {
                    self.add_log(format!("Error al leer archivo: {e}"), NEON_ROSE);
                    self.last_action_banner = Some((format!("Error al leer archivo: {e}"), false));
                    return;
                }
            }
        };

        let (envelope, was_steg) = extract_from_carrier(&raw_data).unwrap_or((raw_data, false));
        if was_steg {
            self.add_log("🖼️ Envoltorio esteganográfico extraído de imagen portadora.", NEON_PURPLE);
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
                let err_msg = e.public_message();
                self.add_log(format!("Fallo de autenticación: {}", err_msg), NEON_ROSE);
                self.last_action_banner = Some((format!("Fallo de autenticación: {err_msg}"), false));
                return;
            }
        };

        if dec.is_duress {
            self.add_log("⚠️ AVISO: Contenido señuelo restaurado (modo coacción).", NEON_AMBER);
        }

        let Ok(payload) = deserialize_payload(&dec.payload) else {
            self.add_log("Error al deserializar payload interno.", NEON_ROSE);
            return;
        };

        let safe_name = safe_basename(&payload.filename, "restored.bin");
        let parent = self.decrypt_files[0].parent().unwrap_or_else(|| std::path::Path::new("."));
        let target_path = parent.join(format!("restored_{safe_name}"));

        if let Err(e) = fs::write(&target_path, &payload.file_data) {
            self.add_log(format!("Error al guardar archivo: {e}"), NEON_ROSE);
            self.last_action_banner = Some((format!("Error al guardar archivo: {e}"), false));
            return;
        }

        self.add_log(
            format!("✅ Archivo restaurado: {:?} ({})", target_path, format_bytes(payload.file_data.len())),
            NEON_EMERALD,
        );
        self.last_action_banner = Some((
            format!("✔ Archivo restaurado con éxito en: {:?} ({})", target_path.file_name().unwrap_or_default(), format_bytes(payload.file_data.len())),
            true,
        ));
    }

    fn render_shamir_tab(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "SHAMIR SECRET SHARING SOBRE GF(256)", "Umbral de secreto perfecto con integridad por HMAC", NEON_CYAN);
            ui.label(
                RichText::new("Divide cualquier archivo en N partes donde cualquier grupo de K fragmentos reconstruye el original y K-1 no revelan información.")
                    .color(TEXT_SECONDARY),
            );
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let pick_btn = egui::Button::new(
                    RichText::new(" 📂 Seleccionar Archivo a Fragmentar... ")
                        .font(FontId::proportional(13.0))
                        .color(TEXT_PRIMARY)
                        .strong(),
                )
                .fill(Color32::from_rgb(26, 36, 56))
                .stroke(Stroke::new(1.0, NEON_CYAN))
                .min_size(Vec2::new(180.0, 36.0));

                if ui.add(pick_btn).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.shamir_input_file = Some(path);
                    }
                }

                if let Some(f) = &self.shamir_input_file {
                    ui.label(RichText::new(f.file_name().unwrap_or_default().to_string_lossy()).color(NEON_EMERALD).strong());
                }
            });

            ui.add_space(10.0);
            ui.add(egui::Slider::new(&mut self.shamir_threshold, 2..=5).text("Umbral de Reconstrucción (K)"));
            ui.add(egui::Slider::new(&mut self.shamir_total, 2..=10).text("Total de Fragmentos (N)"));

            ui.add_space(12.0);
            let can_split = self.shamir_input_file.is_some();
            ui.add_enabled_ui(can_split, |ui| {
                let btn = egui::Button::new(
                    RichText::new(" 🧩 FRAGMENTAR ARCHIVO ")
                        .font(FontId::proportional(14.0))
                        .color(Color32::BLACK)
                        .strong(),
                )
                .fill(NEON_CYAN)
                .rounding(Rounding::same(8.0))
                .min_size(Vec2::new(ui.available_width(), 40.0));

                if ui.add(btn).clicked() {
                    if let Some(path) = self.shamir_input_file.clone() {
                        if let Ok(bytes) = fs::read(&path) {
                            if let Ok(shares) = split_secret(&bytes, self.shamir_threshold, self.shamir_total) {
                                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                                let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                                for (i, s) in shares.iter().enumerate() {
                                    let sp = parent.join(format!("{stem}.part{}.share", i + 1));
                                    fs::write(&sp, s).unwrap();
                                    self.add_log(format!("✨ Fragmento guardado: {:?}", sp), NEON_EMERALD);
                                }
                                self.last_action_banner = Some((format!("✔ Se generaron {} fragmentos con éxito.", shares.len()), true));
                            }
                        }
                    }
                }
            });
        });
    }

    fn render_diagnostics_tab(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "KNOWN ANSWER TESTS (KAT) — AUDITORÍA EN TIEMPO REAL", "Vectores de prueba oficiales de NIST y RFCs", NEON_CYAN);
            ui.label(RichText::new(&self.kat_summary.disclaimer).color(TEXT_SECONDARY).font(FontId::proportional(12.0)));
            ui.add_space(12.0);

            for test in &self.kat_summary.tests {
                Frame::none()
                    .fill(BG_INPUT)
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if test.passed {
                                ui.label(RichText::new(" PASS ").color(Color32::BLACK).background_color(NEON_EMERALD).font(FontId::monospace(11.0)).strong());
                            } else {
                                ui.label(RichText::new(" FAIL ").color(Color32::WHITE).background_color(NEON_ROSE).font(FontId::monospace(11.0)).strong());
                            }
                            ui.label(RichText::new(&test.name).strong());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(&test.source).color(TEXT_MUTED).font(FontId::monospace(11.0)));
                            });
                        });
                    });
                ui.add_space(4.0);
            }

            ui.add_space(10.0);
            if ui.button(" 🔄 Re-ejecutar Diagnóstico KAT ").clicked() {
                self.kat_summary = run_known_answer_tests();
                self.add_log("Diagnóstico KAT re-ejecutado.", NEON_CYAN);
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Project Mirage — Cryptographic Vault (Pure Rust)")
            .with_inner_size([820.0, 740.0])
            .with_min_inner_size([680.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Project Mirage",
        native_options,
        Box::new(|_cc| Ok(Box::new(MirageApp::default()))),
    )
}
