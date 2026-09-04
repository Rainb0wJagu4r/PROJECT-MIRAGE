use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Layout, Margin, RichText, Rounding, Stroke, Vec2,
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
use std::sync::Arc;
use std::time::Instant;

// Pure OLED Black & Electric Neon Purple Palette
const COLOR_BG: Color32 = Color32::from_rgb(0, 0, 0); // True OLED Pitch Black #000000
const COLOR_CARD: Color32 = Color32::from_rgb(12, 10, 18); // Deep Obsidian Purple #0C0A12
const COLOR_CARD_HOVER: Color32 = Color32::from_rgb(20, 16, 30);
const COLOR_INPUT: Color32 = Color32::from_rgb(6, 5, 10);
const COLOR_SUB_BOX: Color32 = Color32::from_rgb(10, 8, 15);

const PURPLE_MAIN: Color32 = Color32::from_rgb(147, 51, 234);
const PURPLE_BRIGHT: Color32 = Color32::from_rgb(168, 85, 247);
const PURPLE_LIGHT: Color32 = Color32::from_rgb(233, 213, 255);
const PURPLE_DEEP: Color32 = Color32::from_rgb(107, 33, 168);
const PURPLE_GLOW: Color32 = Color32::from_rgb(192, 132, 252);

const ACCENT_EMERALD: Color32 = Color32::from_rgb(52, 211, 153);
const ACCENT_AMBER: Color32 = Color32::from_rgb(251, 191, 36);
const ACCENT_ROSE: Color32 = Color32::from_rgb(251, 113, 133);

const TEXT_HEAD: Color32 = Color32::from_rgb(255, 255, 255);
const TEXT_BODY: Color32 = Color32::from_rgb(243, 232, 255);
const TEXT_MUTED: Color32 = Color32::from_rgb(175, 160, 200);
const BORDER_COLOR: Color32 = Color32::from_rgb(50, 36, 75);
const BORDER_PURPLE: Color32 = Color32::from_rgb(124, 58, 237);

#[derive(PartialEq, Clone, Copy)]
enum ActiveTab {
    Encrypt,
    Decrypt,
    Shamir,
    Diagnostics,
}

struct MirageApp {
    active_tab: ActiveTab,

    // Logo Texture
    logo_texture: Option<egui::TextureHandle>,

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

    // Scroll State
    request_scroll_bottom: bool,
    is_scrolled_to_bottom: bool,

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
            logo_texture: None,

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

            request_scroll_bottom: false,
            is_scrolled_to_bottom: false,

            logs: vec![(
                "Native Rust Cryptographic Engine Online [Zero-Network / 100% Memory-Safe]".into(),
                PURPLE_BRIGHT,
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
                    "File loaded: {} ({})",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    format_bytes(bytes.len())
                ),
                PURPLE_BRIGHT,
            );
        }
    }

    fn add_log(&mut self, msg: impl Into<String>, color: Color32) {
        self.logs.push((msg.into(), color));
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    fn ensure_logo_loaded(&mut self, ctx: &egui::Context) {
        if self.logo_texture.is_none() {
            let img_bytes = include_bytes!("../../../assets/wraith_logo.png");
            if let Ok(dyn_img) = image::load_from_memory(img_bytes) {
                let rgba = dyn_img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let pixels = rgba.into_raw();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                self.logo_texture = Some(ctx.load_texture("wraith_logo", color_image, Default::default()));
            }
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
        .fill(COLOR_CARD)
        .stroke(Stroke::new(1.2, BORDER_COLOR))
        .rounding(Rounding::same(14.0))
        .inner_margin(Margin::same(20.0))
}

fn card_header_centered(ui: &mut egui::Ui, tag: &str, title: &str, subtitle: &str) {
    ui.vertical_centered(|ui| {
        ui.horizontal(|ui| {
            let tag_w = 40.0;
            let title_w = title.len() as f32 * 9.5;
            let total_header_w = tag_w + title_w;
            let pad = ((ui.available_width() - total_header_w) / 2.0).max(0.0);
            if pad > 0.0 {
                ui.add_space(pad);
            }
            Frame::none()
                .fill(PURPLE_MAIN)
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::symmetric(8.0, 3.0))
                .show(ui, |ui| {
                    ui.label(RichText::new(tag).font(FontId::proportional(12.5)).color(Color32::WHITE).strong());
                });
            ui.add_space(6.0);
            ui.label(RichText::new(title).font(FontId::proportional(16.0)).color(TEXT_HEAD).strong());
        });
        if !subtitle.is_empty() {
            ui.add_space(3.0);
            ui.label(RichText::new(subtitle).font(FontId::proportional(13.0)).color(TEXT_MUTED));
        }
    });
    ui.add_space(14.0);
}

fn render_option_toggle_card(
    ui: &mut egui::Ui,
    tag: &str,
    title: &str,
    subtitle: &str,
    is_active: &mut bool,
) {
    let card_bg = if *is_active {
        Color32::from_rgb(18, 14, 28)
    } else {
        COLOR_SUB_BOX
    };
    let card_border = if *is_active {
        PURPLE_BRIGHT
    } else {
        BORDER_COLOR
    };

    Frame::none()
        .fill(card_bg)
        .stroke(Stroke::new(1.2, card_border))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(14.0, 10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Tag badge
                Frame::none()
                    .fill(if *is_active { PURPLE_DEEP } else { Color32::from_rgb(26, 20, 36) })
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::symmetric(8.0, 3.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new(tag).font(FontId::monospace(11.5)).color(if *is_active { PURPLE_LIGHT } else { TEXT_MUTED }).strong());
                    });
                ui.add_space(8.0);

                // Option description
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).font(FontId::proportional(13.5)).color(TEXT_HEAD).strong());
                    ui.label(RichText::new(subtitle).font(FontId::proportional(12.0)).color(TEXT_MUTED));
                });

                // Toggle pill button on the right
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (btn_text, btn_bg, btn_fg) = if *is_active {
                        ("  ENABLED  ", PURPLE_MAIN, Color32::WHITE)
                    } else {
                        (" DISABLED ", Color32::from_rgb(24, 18, 34), TEXT_MUTED)
                    };

                    let toggle_btn = egui::Button::new(RichText::new(btn_text).font(FontId::monospace(11.5)).color(btn_fg).strong())
                        .fill(btn_bg)
                        .stroke(Stroke::new(1.0, if *is_active { PURPLE_LIGHT } else { BORDER_COLOR }))
                        .rounding(Rounding::same(14.0))
                        .min_size(Vec2::new(110.0, 30.0));

                    if ui.add(toggle_btn).clicked() {
                        *is_active = !*is_active;
                    }
                });
            });
        });
}

impl eframe::App for MirageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ensure_logo_loaded(ctx);

        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = COLOR_BG;
        visuals.window_fill = COLOR_BG;
        visuals.extreme_bg_color = COLOR_INPUT;
        visuals.override_text_color = Some(TEXT_BODY);

        visuals.widgets.noninteractive.bg_fill = COLOR_CARD;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_COLOR);
        visuals.widgets.noninteractive.rounding = Rounding::same(10.0);

        visuals.widgets.inactive.bg_fill = Color32::from_rgb(22, 18, 32);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_COLOR);
        visuals.widgets.inactive.rounding = Rounding::same(10.0);

        visuals.widgets.hovered.bg_fill = COLOR_CARD_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, PURPLE_BRIGHT);
        visuals.widgets.hovered.rounding = Rounding::same(10.0);

        visuals.widgets.active.bg_fill = Color32::from_rgb(38, 28, 58);
        visuals.widgets.active.bg_stroke = Stroke::new(2.0, PURPLE_BRIGHT);
        visuals.widgets.active.rounding = Rounding::same(10.0);

        visuals.selection.bg_fill = PURPLE_DEEP.linear_multiply(0.5);
        visuals.selection.stroke = Stroke::new(1.5, PURPLE_BRIGHT);

        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(10.0, 10.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        ctx.set_style(style);

        // Header Panel (Centered Hero Logo & Navigation)
        egui::TopBottomPanel::top("top_bar")
            .frame(Frame::none().fill(COLOR_BG).inner_margin(Margin::symmetric(20.0, 16.0)))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    // 1. Centered Logo Image
                    if let Some(texture) = &self.logo_texture {
                        ui.add(egui::Image::new(texture).fit_to_exact_size(Vec2::new(76.0, 76.0)).rounding(Rounding::same(14.0)));
                        ui.add_space(6.0);
                    }

                    // 2. Centered App Title & Subtitle
                    ui.label(
                        RichText::new("PROJECT MIRAGE")
                            .font(FontId::proportional(24.0))
                            .color(TEXT_HEAD)
                            .strong(),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("ARMORED CRYPTOSYSTEM // RUST CORE v2.2.0 (LTS)")
                            .font(FontId::monospace(12.0))
                            .color(PURPLE_GLOW),
                    );

                    ui.add_space(6.0);

                    // 3. Centered KAT Status Badge
                    let (badge_text, badge_fg, badge_bg) = if self.kat_summary.overall {
                        ("[OK] KAT AUDITED: 100% ONLINE (AES-GCM, Camellia, ARIA, ChaCha20, Scrypt-HKDF)", ACCENT_EMERALD, Color32::from_rgb(10, 36, 26))
                    } else {
                        ("[!] ERROR IN KAT SUITE", ACCENT_ROSE, Color32::from_rgb(45, 15, 20))
                    };
                    Frame::none()
                        .fill(badge_bg)
                        .stroke(Stroke::new(1.2, badge_fg))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(14.0, 5.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(badge_text).font(FontId::monospace(11.5)).color(badge_fg).strong());
                        });
                });

                ui.add_space(16.0);

                // 4. Centered Navigation Tab Bar in English
                ui.vertical_centered(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        let total_w = ui.available_width();
                        let tab_btn_w = 165.0;
                        let pad = ((total_w - (tab_btn_w * 4.0 + 24.0)) / 2.0).max(0.0);
                        ui.add_space(pad);

                        let tabs = [
                            (ActiveTab::Encrypt, "ENCRYPT & ARMOR"),
                            (ActiveTab::Decrypt, "DECRYPT"),
                            (ActiveTab::Shamir, "SHAMIR 2-OF-3"),
                            (ActiveTab::Diagnostics, "KAT DIAGNOSTICS"),
                        ];

                        for (tab_type, title) in tabs {
                            let is_active = self.active_tab == tab_type;
                            let bg_color = if is_active { PURPLE_MAIN } else { Color32::from_rgb(20, 16, 30) };
                            let text_color = if is_active { Color32::WHITE } else { TEXT_MUTED };
                            let stroke = if is_active { Stroke::new(1.5, PURPLE_LIGHT) } else { Stroke::new(1.0, BORDER_COLOR) };

                            let btn = egui::Button::new(
                                RichText::new(title)
                                    .font(FontId::proportional(13.5))
                                    .color(text_color)
                                    .strong(),
                            )
                            .fill(bg_color)
                            .stroke(stroke)
                            .rounding(Rounding::same(18.0))
                            .min_size(Vec2::new(tab_btn_w, 36.0));

                            if ui.add(btn).clicked() {
                                self.active_tab = tab_type;
                            }
                            ui.add_space(6.0);
                        }
                    });
                });
            });

        // Bottom Status Bar (Execution Log)
        egui::TopBottomPanel::bottom("bottom_bar")
            .frame(Frame::none().fill(COLOR_CARD).inner_margin(Margin::symmetric(20.0, 8.0)).stroke(Stroke::new(1.0, BORDER_COLOR)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("TERMINAL:").font(FontId::monospace(11.0)).color(PURPLE_BRIGHT).strong());
                    if let Some((msg, color)) = self.logs.last() {
                        ui.label(RichText::new(msg).font(FontId::monospace(11.0)).color(*color));
                    }
                });
            });

        // Central Scrollable Area with Scroll-Down Indicator Detection
        egui::CentralPanel::default().show(ctx, |ui| {
            let mut scroll_area = egui::ScrollArea::vertical().auto_shrink([false, false]);

            if self.request_scroll_bottom {
                scroll_area = scroll_area.vertical_scroll_offset(9999.0);
                self.request_scroll_bottom = false;
            }

            let scroll_output = scroll_area.show(ui, |ui| {
                ui.add_space(10.0);

                let total_width = ui.available_width();
                let target_width = total_width.min(760.0);
                let side_margin = ((total_width - target_width) / 2.0).max(0.0);

                ui.horizontal(|ui| {
                    ui.add_space(side_margin);

                    ui.vertical(|ui| {
                        ui.set_width(target_width);

                        // Notification Banner if present
                        if let Some((msg, success)) = &self.last_action_banner {
                            let (bg, border, fg) = if *success {
                                (Color32::from_rgb(14, 42, 30), ACCENT_EMERALD, Color32::WHITE)
                            } else {
                                (Color32::from_rgb(45, 16, 22), ACCENT_ROSE, Color32::WHITE)
                            };
                            Frame::none()
                                .fill(bg)
                                .stroke(Stroke::new(1.2, border))
                                .rounding(Rounding::same(10.0))
                                .inner_margin(Margin::symmetric(16.0, 12.0))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(msg).font(FontId::proportional(14.0)).color(fg).strong());
                                });
                            ui.add_space(10.0);
                        }

                        match self.active_tab {
                            ActiveTab::Encrypt => self.render_encrypt_tab(ui, target_width),
                            ActiveTab::Decrypt => self.render_decrypt_tab(ui, target_width),
                            ActiveTab::Shamir => self.render_shamir_tab(ui, target_width),
                            ActiveTab::Diagnostics => self.render_diagnostics_tab(ui, target_width),
                        }
                    });

                    ui.add_space(side_margin);
                });

                ui.add_space(60.0);
            });

            // Detect if scrolled to bottom
            let scroll_offset = scroll_output.state.offset.y;
            let content_height = scroll_output.content_size.y;
            let viewport_height = scroll_output.inner_rect.height();
            self.is_scrolled_to_bottom = (scroll_offset + viewport_height) >= (content_height - 60.0) || content_height <= viewport_height;
        });

        // Floating Bottom-Right Scroll Down Indicator Button (Disappears when scrolled to bottom)
        if !self.is_scrolled_to_bottom && self.active_tab != ActiveTab::Diagnostics {
            egui::Area::new(egui::Id::new("floating_scroll_down_btn"))
                .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-24.0, -52.0))
                .show(ctx, |ui| {
                    Frame::none()
                        .fill(Color32::from_rgb(26, 18, 44))
                        .stroke(Stroke::new(1.5, PURPLE_BRIGHT))
                        .rounding(Rounding::same(20.0))
                        .shadow(egui::epaint::Shadow {
                            offset: Vec2::new(0.0, 4.0),
                            blur: 12.0,
                            spread: 2.0,
                            color: Color32::from_black_alpha(180),
                        })
                        .inner_margin(Margin::symmetric(14.0, 8.0))
                        .show(ui, |ui| {
                            let scroll_btn = egui::Button::new(
                                RichText::new("SCROLL DOWN")
                                    .font(FontId::proportional(12.5))
                                    .color(Color32::WHITE)
                                    .strong(),
                            )
                            .fill(PURPLE_MAIN)
                            .rounding(Rounding::same(14.0));

                            if ui.add(scroll_btn).clicked() {
                                self.request_scroll_bottom = true;
                            }
                        });
                });
        }
    }
}

impl MirageApp {
    fn render_encrypt_tab(&mut self, ui: &mut egui::Ui, card_width: f32) {
        let inner_width = card_width - 40.0;

        // Card 1: File Selection (Fully Centered)
        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "01", "PROTECTED FILE", "Select the confidential payload file to encrypt");

            ui.vertical_centered(|ui| {
                Frame::none()
                    .fill(COLOR_SUB_BOX)
                    .stroke(Stroke::new(1.2, if self.encrypt_file.is_some() { PURPLE_BRIGHT } else { BORDER_COLOR }))
                    .rounding(Rounding::same(12.0))
                    .inner_margin(Margin::symmetric(24.0, 16.0))
                    .show(ui, |ui| {
                        ui.set_width(inner_width - 32.0);
                        ui.vertical_centered(|ui| {
                            let pick_btn = egui::Button::new(
                                RichText::new("  SELECT FILE...  ")
                                    .font(FontId::proportional(14.0))
                                    .color(TEXT_HEAD)
                                    .strong(),
                            )
                            .fill(Color32::from_rgb(38, 28, 56))
                            .stroke(Stroke::new(1.2, PURPLE_BRIGHT))
                            .rounding(Rounding::same(12.0))
                            .min_size(Vec2::new(240.0, 42.0));

                            if ui.add(pick_btn).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.set_encrypt_file(path);
                                }
                            }

                            ui.add_space(8.0);

                            if let Some(file) = &self.encrypt_file {
                                ui.label(
                                    RichText::new(format!("[OK] {}", file.file_name().unwrap_or_default().to_string_lossy()))
                                        .font(FontId::proportional(15.0))
                                        .color(ACCENT_EMERALD)
                                        .strong(),
                                );
                                ui.add_space(2.0);
                                ui.label(
                                    RichText::new(format!("Size: {}", format_bytes(self.encrypt_file_size)))
                                        .font(FontId::proportional(13.0))
                                        .color(TEXT_MUTED),
                                );

                                if !self.encrypt_file_hash.is_empty() {
                                    ui.add_space(8.0);
                                    Frame::none()
                                        .fill(COLOR_INPUT)
                                        .stroke(Stroke::new(1.0, BORDER_COLOR))
                                        .rounding(Rounding::same(8.0))
                                        .inner_margin(Margin::symmetric(14.0, 8.0))
                                        .show(ui, |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(RichText::new("SHA3-256:").font(FontId::monospace(11.5)).color(PURPLE_LIGHT).strong());
                                                ui.label(RichText::new(&self.encrypt_file_hash).font(FontId::monospace(11.5)).color(TEXT_HEAD));
                                            });
                                        });
                                }
                            } else {
                                ui.label(
                                    RichText::new("No file loaded in memory")
                                        .font(FontId::proportional(13.0))
                                        .color(TEXT_MUTED),
                                );
                            }
                        });
                    });
            });
        });

        ui.add_space(14.0);

        // Card 2: Password & Entropy (Fully Centered with Equal Sizing)
        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "02", "AUTHENTICATION & ENTROPY", "Master passphrase derived via Scrypt (N=131072, r=8, p=1)");

            ui.vertical_centered(|ui| {
                let center_box_w = 460.0_f32.min(inner_width - 32.0);

                // Password row
                ui.label(RichText::new("Master Passphrase:").font(FontId::proportional(14.0)).color(TEXT_BODY).strong());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let total_w = ui.available_width();
                    let pad = ((total_w - center_box_w) / 2.0).max(0.0);
                    if pad > 0.0 { ui.add_space(pad); }

                    let input_w = center_box_w - 90.0;
                    let mut edit = egui::TextEdit::singleline(&mut self.encrypt_password)
                        .font(FontId::proportional(14.0))
                        .desired_width(input_w)
                        .margin(Margin::symmetric(10.0, 8.0));
                    if !self.encrypt_show_password {
                        edit = edit.password(true);
                    }
                    ui.add(edit);

                    let eye_btn_text = if self.encrypt_show_password { " HIDE " } else { " SHOW " };
                    let eye_btn = egui::Button::new(RichText::new(eye_btn_text).font(FontId::proportional(12.0)).strong())
                        .fill(Color32::from_rgb(26, 20, 38))
                        .stroke(Stroke::new(1.0, BORDER_COLOR))
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(80.0, 36.0));
                    if ui.add(eye_btn).clicked() {
                        self.encrypt_show_password = !self.encrypt_show_password;
                    }
                });

                if !self.encrypt_password.is_empty() {
                    ui.add_space(8.0);
                    let assessment = assess_password_strength(&self.encrypt_password);
                    let (bits_label, color, fill_pct) = match assessment {
                        Ok(bits) => {
                            let pct = ((bits as f32) / 100.0).clamp(0.0, 1.0);
                            (format!("[OK] Strength: ~{bits} bits of entropy (Meets security policy)"), ACCENT_EMERALD, pct)
                        }
                        Err(err) => (format!("[!] Warning: {err}"), ACCENT_ROSE, 0.25),
                    };

                    ui.label(RichText::new(bits_label).font(FontId::monospace(11.5)).color(color).strong());
                    ui.add_space(3.0);
                    ui.add_sized([center_box_w, 8.0], egui::ProgressBar::new(fill_pct).fill(color).animate(false));
                }

                ui.add_space(12.0);

                // 2FA Symmetric Field
                ui.label(RichText::new("Optional Second Factor Secret (2FA):").font(FontId::proportional(14.0)).color(TEXT_BODY).strong());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let total_w = ui.available_width();
                    let pad = ((total_w - center_box_w) / 2.0).max(0.0);
                    if pad > 0.0 { ui.add_space(pad); }

                    ui.add(
                        egui::TextEdit::singleline(&mut self.encrypt_2fa)
                            .font(FontId::proportional(14.0))
                            .password(true)
                            .desired_width(center_box_w)
                            .margin(Margin::symmetric(10.0, 8.0)),
                    );
                });
            });
        });

        ui.add_space(14.0);

        // Card 3: Cryptographic Configuration & Mirage-C4 Cascade Breakdown
        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "03", "CRYPTOGRAPHIC SUITE & OPTIONS", "Configure core cipher cascade and armored defense modules");

            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    let total_w = ui.available_width();
                    let pad = (total_w - 480.0) / 2.0;
                    if pad > 0.0 {
                        ui.add_space(pad);
                    }
                    ui.label(RichText::new("Cipher Algorithm:").font(FontId::proportional(14.0)).color(TEXT_BODY).strong());
                    egui::ComboBox::from_id_salt("algo_select_native")
                        .selected_text(match self.encrypt_algorithm {
                            Algorithm::CascadeC4 => "Mirage-C4 v2 (4-Layer Non-Linear Cascade)",
                            Algorithm::AesGcm => "AES-256-GCM (NIST Single Standard)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.encrypt_algorithm,
                                Algorithm::CascadeC4,
                                "Mirage-C4 v2 (4-Layer Non-Linear Cascade)",
                            );
                            ui.selectable_value(
                                &mut self.encrypt_algorithm,
                                Algorithm::AesGcm,
                                "AES-256-GCM (NIST Single Standard)",
                            );
                        });
                });
            });

            // Mirage-C4 Cascade Breakdown Box Centered
            if self.encrypt_algorithm == Algorithm::CascadeC4 {
                ui.add_space(12.0);
                Frame::none()
                    .fill(COLOR_SUB_BOX)
                    .stroke(Stroke::new(1.2, BORDER_PURPLE))
                    .rounding(Rounding::same(10.0))
                    .inner_margin(Margin::symmetric(16.0, 14.0))
                    .show(ui, |ui| {
                        ui.set_width(inner_width - 32.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("MIRAGE-C4 v2 CASCADE ARCHITECTURE:")
                                    .font(FontId::proportional(13.5))
                                    .color(PURPLE_LIGHT)
                                    .strong(),
                            );
                        });
                        ui.add_space(8.0);

                        let layers = [
                            ("Layer 1", "Camellia-256-CBC", "128-bit Block Cipher (RFC 3713 / NESSIE)"),
                            ("Layer 2", "ChaCha20", "High-speed Stream Cipher with 512-bit state (RFC 8439)"),
                            ("Layer 3", "ARIA-256-CBC", "Korean Standard 128-bit Block Cipher (RFC 5794)"),
                            ("Layer 4", "AES-256-GCM", "Authenticated Cipher with Context-Bound AAD Tag (NIST SP 800-38D)"),
                        ];

                        for (num, algo, desc) in layers {
                            ui.horizontal(|ui| {
                                Frame::none()
                                    .fill(Color32::from_rgb(26, 20, 42))
                                    .stroke(Stroke::new(1.0, PURPLE_DEEP))
                                    .rounding(Rounding::same(5.0))
                                    .inner_margin(Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(num).font(FontId::monospace(11.0)).color(PURPLE_BRIGHT).strong());
                                    });
                                ui.label(RichText::new(algo).font(FontId::proportional(13.0)).color(TEXT_HEAD).strong());
                                ui.label(RichText::new(format!("-> {}", desc)).font(FontId::proportional(12.0)).color(TEXT_MUTED));
                            });
                            ui.add_space(2.0);
                        }

                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("• Armored KDF: Scrypt (N=131072, r=8, p=1) + HKDF-SHA256 with domain-separated subkeys and RAM zeroization.")
                                .font(FontId::proportional(11.5))
                                .color(TEXT_MUTED),
                        );
                    });
            }

            ui.add_space(14.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("ADVANCED DEFENSE MODULES:").font(FontId::proportional(13.0)).color(PURPLE_LIGHT).strong());
            });
            ui.add_space(6.0);

            // Centered Option Cards in English
            render_option_toggle_card(
                ui,
                "PADME",
                "Padme Length Quantization",
                "Mitigates traffic size leakage (<= 12% overhead - PETS 2019 standard)",
                &mut self.encrypt_padme,
            );

            ui.add_space(6.0);
            render_option_toggle_card(
                ui,
                "SHAMIR",
                "2-of-3 Secret Sharing (GF-256)",
                "Generates 3 independent mathematical shares; any 2 required to restore",
                &mut self.encrypt_shamir,
            );

            ui.add_space(6.0);
            // Steganography Option Card
            let is_stego_active = self.encrypt_carrier_file.is_some();
            Frame::none()
                .fill(if is_stego_active { Color32::from_rgb(18, 14, 28) } else { COLOR_SUB_BOX })
                .stroke(Stroke::new(1.2, if is_stego_active { PURPLE_BRIGHT } else { BORDER_COLOR }))
                .rounding(Rounding::same(10.0))
                .inner_margin(Margin::symmetric(14.0, 10.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        Frame::none()
                            .fill(if is_stego_active { PURPLE_DEEP } else { Color32::from_rgb(26, 20, 36) })
                            .rounding(Rounding::same(6.0))
                            .inner_margin(Margin::symmetric(8.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new("STEGO").font(FontId::monospace(11.5)).color(if is_stego_active { PURPLE_LIGHT } else { TEXT_MUTED }).strong());
                            });
                        ui.add_space(8.0);

                        ui.vertical(|ui| {
                            ui.label(RichText::new("Carrier Steganography (PNG / JPEG)").font(FontId::proportional(13.5)).color(TEXT_HEAD).strong());
                            if let Some(c) = &self.encrypt_carrier_file {
                                ui.label(RichText::new(format!("[OK] Carrier: {}", c.file_name().unwrap_or_default().to_string_lossy())).font(FontId::proportional(12.5)).color(ACCENT_EMERALD).strong());
                            } else {
                                ui.label(RichText::new("Injects the .wraith container into a genuine image file").font(FontId::proportional(12.0)).color(TEXT_MUTED));
                            }
                        });

                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if self.encrypt_carrier_file.is_some() {
                                if ui.button(RichText::new(" [X] REMOVE ").font(FontId::monospace(11.0)).color(ACCENT_ROSE)).clicked() {
                                    self.encrypt_carrier_file = None;
                                }
                            } else {
                                let stego_btn = egui::Button::new(RichText::new("  CHOOSE IMAGE...  ").font(FontId::proportional(12.0)).strong())
                                    .fill(Color32::from_rgb(32, 24, 48))
                                    .stroke(Stroke::new(1.0, BORDER_COLOR))
                                    .rounding(Rounding::same(12.0));

                                if ui.add(stego_btn).clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("Images", &["png", "jpg", "jpeg"])
                                        .pick_file()
                                    {
                                        self.encrypt_carrier_file = Some(path);
                                    }
                                }
                            }
                        });
                    });
                });

            ui.add_space(6.0);
            // Duress Mode Option Card
            render_option_toggle_card(
                ui,
                "DURESS",
                "Duress Decoy Mode",
                "Unlocks a harmless decoy file when forced under duress",
                &mut self.encrypt_duress_enabled,
            );

            if self.encrypt_duress_enabled {
                ui.add_space(6.0);
                Frame::none()
                    .fill(COLOR_SUB_BOX)
                    .stroke(Stroke::new(1.0, PURPLE_BRIGHT))
                    .rounding(Rounding::same(10.0))
                    .inner_margin(Margin::same(14.0))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.horizontal(|ui| {
                                let total_w = ui.available_width();
                                let pad = (total_w - 420.0) / 2.0;
                                if pad > 0.0 { ui.add_space(pad); }
                                ui.label(RichText::new("Decoy Passphrase:").font(FontId::proportional(13.5)).color(TEXT_BODY).strong());
                                ui.add(egui::TextEdit::singleline(&mut self.encrypt_duress_password).password(true).desired_width(240.0));
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                let total_w = ui.available_width();
                                let pad = (total_w - 380.0) / 2.0;
                                if pad > 0.0 { ui.add_space(pad); }
                                let pick_decoy_btn = egui::Button::new(RichText::new("  Select Decoy File...  ").font(FontId::proportional(12.5)))
                                    .fill(Color32::from_rgb(32, 24, 48))
                                    .stroke(Stroke::new(1.0, BORDER_COLOR))
                                    .rounding(Rounding::same(8.0));

                                if ui.add(pick_decoy_btn).clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                                        self.encrypt_duress_file = Some(path);
                                    }
                                }
                                if let Some(df) = &self.encrypt_duress_file {
                                    ui.label(RichText::new(format!("[OK] {}", df.file_name().unwrap_or_default().to_string_lossy())).font(FontId::proportional(12.5)).color(TEXT_HEAD));
                                }
                            });
                        });
                    });
            }
        });

        ui.add_space(20.0);

        // Action Button Centered (Full Width matching card, 50px height)
        let can_encrypt = self.encrypt_file.is_some() && !self.encrypt_password.is_empty();
        ui.add_enabled_ui(can_encrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  ENCRYPT .WRAITH CONTAINER  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::WHITE)
                    .strong(),
            )
            .fill(PURPLE_MAIN)
            .stroke(Stroke::new(1.5, PURPLE_LIGHT))
            .rounding(Rounding::same(14.0))
            .min_size(Vec2::new(card_width, 50.0));

            if ui.add(btn).clicked() {
                self.perform_encryption();
            }
        });
    }

    fn perform_encryption(&mut self) {
        let Some(file_path) = self.encrypt_file.clone() else { return };
        let Ok(file_bytes) = fs::read(&file_path) else {
            self.add_log("Error reading source payload file.", ACCENT_ROSE);
            self.last_action_banner = Some(("Error reading source payload file.".into(), false));
            return;
        };

        let start = Instant::now();
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();

        let Ok(payload) = serialize_payload(&filename, &file_bytes, 0) else {
            self.add_log("Error serializing payload.", ACCENT_ROSE);
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
                self.add_log(format!("Encryption failed: {}", err_msg), ACCENT_ROSE);
                self.last_action_banner = Some((format!("Encryption failed: {err_msg}"), false));
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
                self.add_log(format!("Share saved: {:?}", share_path), ACCENT_EMERALD);
            }
            self.last_action_banner = Some((format!("2-of-3 Shamir secret sharing completed ({elapsed_ms:.1} ms)"), true));
        } else {
            let out_path = file_path.with_extension("wraith");
            if let Err(e) = fs::write(&out_path, &final_data) {
                self.add_log(format!("Error writing output file: {e}"), ACCENT_ROSE);
                self.last_action_banner = Some((format!("Error writing output file: {e}"), false));
                return;
            }
            self.add_log(
                format!("Saved: {:?} ({elapsed_ms:.1} ms)", out_path),
                ACCENT_EMERALD,
            );
            self.last_action_banner = Some((format!("Encrypted container saved to {:?} ({elapsed_ms:.1} ms)", out_path.file_name().unwrap_or_default()), true));
        }
    }

    fn render_decrypt_tab(&mut self, ui: &mut egui::Ui, card_width: f32) {
        let inner_width = card_width - 40.0;

        // Card 1: Decrypt File Selection Centered
        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "01", "ENCRYPTED ARCHIVE OR SHARES", "Load the .wraith container or .share parts");

            ui.vertical_centered(|ui| {
                Frame::none()
                    .fill(COLOR_SUB_BOX)
                    .stroke(Stroke::new(1.2, if !self.decrypt_files.is_empty() { PURPLE_BRIGHT } else { BORDER_COLOR }))
                    .rounding(Rounding::same(12.0))
                    .inner_margin(Margin::symmetric(24.0, 16.0))
                    .show(ui, |ui| {
                        ui.set_width(inner_width - 32.0);
                        ui.vertical_centered(|ui| {
                            let pick_btn = egui::Button::new(
                                RichText::new("  SELECT (.WRAITH / .SHARE)...  ")
                                    .font(FontId::proportional(14.0))
                                    .color(TEXT_HEAD)
                                    .strong(),
                            )
                            .fill(Color32::from_rgb(38, 28, 56))
                            .stroke(Stroke::new(1.2, PURPLE_BRIGHT))
                            .rounding(Rounding::same(12.0))
                            .min_size(Vec2::new(260.0, 42.0));

                            if ui.add(pick_btn).clicked() {
                                if let Some(files) = rfd::FileDialog::new().pick_files() {
                                    self.decrypt_files = files;
                                }
                            }

                            ui.add_space(8.0);

                            if !self.decrypt_files.is_empty() {
                                ui.label(
                                    RichText::new(format!("[OK] {} file(s) selected", self.decrypt_files.len()))
                                        .font(FontId::proportional(14.5))
                                        .color(ACCENT_EMERALD)
                                        .strong(),
                                );
                                ui.add_space(4.0);
                                for f in &self.decrypt_files {
                                    ui.label(RichText::new(format!("• {:?}", f.file_name().unwrap_or_default())).font(FontId::monospace(11.5)).color(TEXT_MUTED));
                                }
                            } else {
                                ui.label(RichText::new("No files loaded in memory").font(FontId::proportional(13.0)).color(TEXT_MUTED));
                            }
                        });
                    });
            });
        });

        ui.add_space(14.0);

        // Card 2: Credentials Centered
        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "02", "AUTHENTICATION CREDENTIALS", "AEAD authentication verified prior to ciphertext restoration");

            ui.vertical_centered(|ui| {
                let center_box_w = 460.0_f32.min(inner_width - 32.0);

                ui.label(RichText::new("Passphrase:").font(FontId::proportional(14.0)).color(TEXT_BODY).strong());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let total_w = ui.available_width();
                    let pad = ((total_w - center_box_w) / 2.0).max(0.0);
                    if pad > 0.0 { ui.add_space(pad); }

                    let input_w = center_box_w - 90.0;
                    let mut edit = egui::TextEdit::singleline(&mut self.decrypt_password)
                        .font(FontId::proportional(14.0))
                        .desired_width(input_w)
                        .margin(Margin::symmetric(10.0, 8.0));
                    if !self.decrypt_show_password {
                        edit = edit.password(true);
                    }
                    ui.add(edit);

                    let eye_btn_text = if self.decrypt_show_password { " HIDE " } else { " SHOW " };
                    let eye_btn = egui::Button::new(RichText::new(eye_btn_text).font(FontId::proportional(12.0)).strong())
                        .fill(Color32::from_rgb(26, 20, 38))
                        .stroke(Stroke::new(1.0, BORDER_COLOR))
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(80.0, 36.0));
                    if ui.add(eye_btn).clicked() {
                        self.decrypt_show_password = !self.decrypt_show_password;
                    }
                });

                ui.add_space(12.0);

                ui.label(RichText::new("Optional Second Factor Secret (2FA):").font(FontId::proportional(14.0)).color(TEXT_BODY).strong());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let total_w = ui.available_width();
                    let pad = ((total_w - center_box_w) / 2.0).max(0.0);
                    if pad > 0.0 { ui.add_space(pad); }

                    ui.add(
                        egui::TextEdit::singleline(&mut self.decrypt_2fa)
                            .font(FontId::proportional(14.0))
                            .password(true)
                            .desired_width(center_box_w)
                            .margin(Margin::symmetric(10.0, 8.0)),
                    );
                });
            });
        });

        ui.add_space(20.0);

        let can_decrypt = !self.decrypt_files.is_empty() && !self.decrypt_password.is_empty();
        ui.add_enabled_ui(can_decrypt, |ui| {
            let btn = egui::Button::new(
                RichText::new("  DECRYPT & RESTORE PAYLOAD  ")
                    .font(FontId::proportional(16.0))
                    .color(Color32::WHITE)
                    .strong(),
            )
            .fill(Color32::from_rgb(16, 130, 85))
            .stroke(Stroke::new(1.5, ACCENT_EMERALD))
            .rounding(Rounding::same(14.0))
            .min_size(Vec2::new(card_width, 50.0));

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
                    self.add_log(format!("Share combination error: {}", err_msg), ACCENT_ROSE);
                    self.last_action_banner = Some((format!("Share combination error: {err_msg}"), false));
                    return;
                }
            }
        } else {
            match fs::read(&self.decrypt_files[0]) {
                Ok(d) => d,
                Err(e) => {
                    self.add_log(format!("Error reading archive: {e}"), ACCENT_ROSE);
                    self.last_action_banner = Some((format!("Error reading archive: {e}"), false));
                    return;
                }
            }
        };

        let (envelope, was_steg) = extract_from_carrier(&raw_data).unwrap_or((raw_data, false));
        if was_steg {
            self.add_log("Container extracted from carrier image.", PURPLE_BRIGHT);
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
                self.add_log(format!("Authentication failed: {}", err_msg), ACCENT_ROSE);
                self.last_action_banner = Some((format!("Authentication failed: {err_msg}"), false));
                return;
            }
        };

        if dec.is_duress {
            self.add_log("NOTICE: Decoy payload restored (duress mode).", ACCENT_AMBER);
        }

        let Ok(payload) = deserialize_payload(&dec.payload) else {
            self.add_log("Error deserializing payload.", ACCENT_ROSE);
            return;
        };

        let safe_name = safe_basename(&payload.filename, "restored.bin");
        let parent = self.decrypt_files[0].parent().unwrap_or_else(|| std::path::Path::new("."));
        let target_path = parent.join(format!("restored_{safe_name}"));

        if let Err(e) = fs::write(&target_path, &payload.file_data) {
            self.add_log(format!("Error saving restored file: {e}"), ACCENT_ROSE);
            self.last_action_banner = Some((format!("Error saving restored file: {e}"), false));
            return;
        }

        self.add_log(
            format!("Payload restored: {:?} ({})", target_path, format_bytes(payload.file_data.len())),
            ACCENT_EMERALD,
        );
        self.last_action_banner = Some((
            format!("Payload restored successfully: {:?} ({})", target_path.file_name().unwrap_or_default(), format_bytes(payload.file_data.len())),
            true,
        ));
    }

    fn render_shamir_tab(&mut self, ui: &mut egui::Ui, card_width: f32) {
        let inner_width = card_width - 40.0;

        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "01", "SHAMIR SECRET SHARING 2-OF-3", "Split any secret payload into independent mathematical shares over GF(256)");

            ui.vertical_centered(|ui| {
                Frame::none()
                    .fill(COLOR_SUB_BOX)
                    .stroke(Stroke::new(1.2, if self.shamir_input_file.is_some() { PURPLE_BRIGHT } else { BORDER_COLOR }))
                    .rounding(Rounding::same(12.0))
                    .inner_margin(Margin::symmetric(24.0, 16.0))
                    .show(ui, |ui| {
                        ui.set_width(inner_width - 32.0);
                        ui.vertical_centered(|ui| {
                            let pick_btn = egui::Button::new(
                                RichText::new("  SELECT FILE TO SPLIT...  ")
                                    .font(FontId::proportional(14.0))
                                    .color(TEXT_HEAD)
                                    .strong(),
                            )
                            .fill(Color32::from_rgb(38, 28, 56))
                            .stroke(Stroke::new(1.2, PURPLE_BRIGHT))
                            .rounding(Rounding::same(12.0))
                            .min_size(Vec2::new(260.0, 42.0));

                            if ui.add(pick_btn).clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.shamir_input_file = Some(path);
                                }
                            }

                            ui.add_space(8.0);

                            if let Some(f) = &self.shamir_input_file {
                                ui.label(RichText::new(format!("[OK] {}", f.file_name().unwrap_or_default().to_string_lossy())).font(FontId::proportional(14.5)).color(ACCENT_EMERALD).strong());
                            } else {
                                ui.label(RichText::new("No file selected").font(FontId::proportional(13.0)).color(TEXT_MUTED));
                            }
                        });
                    });

                ui.add_space(14.0);
                ui.add(egui::Slider::new(&mut self.shamir_threshold, 2..=5).text("Required Threshold (K)").text_color(TEXT_HEAD));
                ui.add_space(4.0);
                ui.add(egui::Slider::new(&mut self.shamir_total, 2..=10).text("Total Shares (N)").text_color(TEXT_HEAD));
            });

            ui.add_space(18.0);
            let can_split = self.shamir_input_file.is_some();
            ui.add_enabled_ui(can_split, |ui| {
                let btn = egui::Button::new(
                    RichText::new("  SPLIT FILE INTO SHARES  ")
                        .font(FontId::proportional(16.0))
                        .color(Color32::WHITE)
                        .strong(),
                )
                .fill(PURPLE_MAIN)
                .stroke(Stroke::new(1.2, PURPLE_LIGHT))
                .rounding(Rounding::same(12.0))
                .min_size(Vec2::new(card_width, 48.0));

                if ui.add(btn).clicked() {
                    if let Some(path) = self.shamir_input_file.clone() {
                        if let Ok(bytes) = fs::read(&path) {
                            if let Ok(shares) = split_secret(&bytes, self.shamir_threshold, self.shamir_total) {
                                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                                let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                                for (i, s) in shares.iter().enumerate() {
                                    let sp = parent.join(format!("{stem}.part{}.share", i + 1));
                                    fs::write(&sp, s).unwrap();
                                    self.add_log(format!("Share saved: {:?}", sp), ACCENT_EMERALD);
                                }
                                self.last_action_banner = Some((format!("Generated {} shares successfully.", shares.len()), true));
                            }
                        }
                    }
                }
            });
        });
    }

    fn render_diagnostics_tab(&mut self, ui: &mut egui::Ui, card_width: f32) {
        let inner_width = card_width - 40.0;

        card_frame().show(ui, |ui| {
            ui.set_width(inner_width);
            card_header_centered(ui, "KAT", "KNOWN ANSWER TESTS — LIVE DIAGNOSTICS", "Official published reference test vectors (NIST, RFCs)");
            ui.label(RichText::new(&self.kat_summary.disclaimer).color(TEXT_MUTED).font(FontId::proportional(12.5)));
            ui.add_space(12.0);

            for test in &self.kat_summary.tests {
                Frame::none()
                    .fill(COLOR_INPUT)
                    .stroke(Stroke::new(1.0, BORDER_COLOR))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::symmetric(14.0, 10.0))
                    .show(ui, |ui| {
                        ui.set_width(inner_width - 28.0);
                        ui.horizontal(|ui| {
                            if test.passed {
                                ui.label(RichText::new(" PASS ").color(Color32::BLACK).background_color(ACCENT_EMERALD).font(FontId::monospace(10.5)).strong());
                            } else {
                                ui.label(RichText::new(" FAIL ").color(Color32::WHITE).background_color(ACCENT_ROSE).font(FontId::monospace(10.5)).strong());
                            }
                            ui.label(RichText::new(&test.name).font(FontId::proportional(13.5)).color(TEXT_HEAD).strong());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(&test.source).color(TEXT_MUTED).font(FontId::monospace(11.0)));
                            });
                        });
                    });
                ui.add_space(5.0);
            }

            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                let retest_btn = egui::Button::new(RichText::new("  RE-RUN KAT DIAGNOSTICS  ").font(FontId::proportional(13.5)).strong())
                    .fill(Color32::from_rgb(32, 24, 48))
                    .stroke(Stroke::new(1.2, PURPLE_BRIGHT))
                    .rounding(Rounding::same(10.0))
                    .min_size(Vec2::new(260.0, 40.0));

                if ui.add(retest_btn).clicked() {
                    self.kat_summary = run_known_answer_tests();
                    self.add_log("KAT diagnostics refreshed.", PURPLE_BRIGHT);
                }
            });
        });
    }
}

fn load_app_icon() -> Option<Arc<egui::IconData>> {
    let icon_bytes = include_bytes!("../../../assets/icon.png");
    if let Ok(image) = image::load_from_memory(icon_bytes) {
        let rgba = image.to_rgba8();
        let (width, height) = rgba.dimensions();
        return Some(Arc::new(egui::IconData {
            rgba: rgba.into_raw(),
            width,
            height,
        }));
    }
    None
}

fn main() -> eframe::Result<()> {
    let icon = load_app_icon();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Project Mirage — Armored Cryptosystem (LTS)")
        .with_inner_size([800.0, 880.0])
        .with_min_inner_size([560.0, 600.0]);

    if let Some(i) = icon {
        viewport = viewport.with_icon(i);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Project Mirage",
        native_options,
        Box::new(|_cc| Ok(Box::new(MirageApp::default()))),
    )
}
