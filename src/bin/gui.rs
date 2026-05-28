#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // Hide console window on Windows in release builds

use eframe::egui;
use std::collections::HashMap;
use ircx_sspi::vault::{
    UserLevel, VaultAccount, load_master_key, load_and_decrypt_vault,
    encrypt_and_save_vault, ensure_master_key, is_non_existent_domain
};
use ircx_sspi::ntlm::calculate_nt_hash;

fn main() -> eframe::Result<()> {
    // Automatically verify/generate the master key on startup
    let _ = ensure_master_key();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("IRCX NTLM Vault Manager")
            .with_inner_size([920.0, 620.0])
            .with_min_inner_size([750.0, 500.0])
            .with_resizable(true),
        follow_system_theme: true,
        default_theme: eframe::Theme::Dark,
        ..Default::default()
    };

    eframe::run_native(
        "IRCX NTLM Vault Manager",
        options,
        Box::new(|cc| {
            let is_dark = cc.egui_ctx.style().visuals.dark_mode;
            apply_theme_overrides(&cc.egui_ctx, is_dark);
            let mut app = VaultManagerApp::new();
            app.last_dark_mode = Some(is_dark);
            Box::new(app)
        }),
    )
}

fn apply_theme_overrides(ctx: &egui::Context, is_dark: bool) {
    let mut style = (*ctx.style()).clone();

    // Start from egui defaults for the current mode, then apply shared accents.
    style.visuals = if is_dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    // Smooth rounding for a modern look.
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);

    // Keep a single accent color across dark/light themes.
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(46, 115, 230);
    style.visuals.widgets.active.bg_fill = style.visuals.selection.bg_fill;

    ctx.set_style(style);
}

struct VaultManagerApp {
    users: HashMap<String, VaultAccount>,
    master_key: Option<[u8; 32]>,
    
    // UI Status Banner
    status_message: Option<(String, bool)>, // (Message content, is_success)
    status_time: Option<std::time::Instant>,
    
    // Form Inputs
    editing_username: Option<String>, // Some(username) if currently editing, None if adding a new user
    input_username: String,
    input_password: String,
    input_domain: String,
    input_level: UserLevel,
    show_password: bool,
    
    // Confirmation State
    pending_delete: Option<String>,
    last_dark_mode: Option<bool>,
}

impl VaultManagerApp {
    fn new() -> Self {
        let mut app = Self {
            users: HashMap::new(),
            master_key: None,
            status_message: None,
            status_time: None,
            editing_username: None,
            input_username: String::new(),
            input_password: String::new(),
            input_domain: String::new(),
            input_level: UserLevel::Guide,
            show_password: false,
            pending_delete: None,
            last_dark_mode: None,
        };
        app.reload_vault();
        app
    }

    fn reload_vault(&mut self) {
        match load_master_key() {
            Ok(key) => {
                self.master_key = Some(key);
                match load_and_decrypt_vault(&key) {
                    Ok(map) => {
                        self.users = map;
                    }
                    Err(e) => {
                        self.show_status(format!("Failed to decrypt vault: {:?}", e), false);
                    }
                }
            }
            Err(e) => {
                self.show_status(format!("Failed to load master.key: {:?}", e), false);
            }
        }
    }

    fn show_status(&mut self, msg: String, is_success: bool) {
        self.status_message = Some((msg, is_success));
        self.status_time = Some(std::time::Instant::now());
    }

    fn reset_form(&mut self) {
        self.editing_username = None;
        self.input_username.clear();
        self.input_password.clear();
        self.input_domain.clear();
        self.input_level = UserLevel::Guide;
        self.show_password = false;
    }

    fn handle_save(&mut self) {
        let username_clean = self.input_username.trim().to_string();
        if username_clean.is_empty() {
            self.show_status("Username cannot be empty!".to_string(), false);
            return;
        }

        let is_edit = self.editing_username.is_some();

        // Password validation: required for new user
        if !is_edit && self.input_password.is_empty() {
            self.show_status("Password is required for new users!".to_string(), false);
            return;
        }

        let key = match self.master_key {
            Some(k) => k,
            None => {
                self.show_status("Cannot save: Master key is missing/unloaded!".to_string(), false);
                return;
            }
        };

        // Normalize domain
        let db_domain = if is_non_existent_domain(&self.input_domain) {
            "".to_string()
        } else {
            self.input_domain.trim().to_lowercase()
        };

        // Get or derive NT hash
        let nt_hash_hex = if self.input_password.is_empty() && is_edit {
            // Keep existing password
            let old_username = self.editing_username.as_ref().unwrap();
            match self.users.get(old_username) {
                Some(acc) => acc.nt_hash.clone(),
                None => {
                    self.show_status("Critical error: Editing user missing in vault!".to_string(), false);
                    return;
                }
            }
        } else {
            // Calculate new NT hash (MD4)
            let raw_hash = calculate_nt_hash(&self.input_password);
            hex::encode(raw_hash)
        };

        // Insert / Update map
        self.users.insert(username_clean.to_lowercase(), VaultAccount {
            username: username_clean,
            nt_hash: nt_hash_hex,
            domain: db_domain,
            level: self.input_level,
        });

        // Write directly back to vault
        match encrypt_and_save_vault(&key, &self.users) {
            Ok(_) => {
                if is_edit {
                    self.show_status("User successfully updated in vault!".to_string(), true);
                } else {
                    self.show_status("User successfully created in vault!".to_string(), true);
                }
                self.reset_form();
            }
            Err(e) => {
                self.show_status(format!("Failed to save vault: {:?}", e), false);
            }
        }
    }

    fn handle_delete(&mut self, username: String) {
        let key = match self.master_key {
            Some(k) => k,
            None => {
                self.show_status("Cannot delete: Master key is missing!".to_string(), false);
                return;
            }
        };

        if self.users.remove(&username).is_some() {
            match encrypt_and_save_vault(&key, &self.users) {
                Ok(_) => {
                    self.show_status(format!("User '{}' successfully deleted.", username), true);
                    if self.editing_username.as_ref() == Some(&username) {
                        self.reset_form();
                    }
                }
                Err(e) => {
                    self.show_status(format!("Deleted from cache but failed to save file: {:?}", e), false);
                }
            }
        } else {
            self.show_status("User not found!".to_string(), false);
        }
    }
}

impl eframe::App for VaultManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let is_dark = ctx.style().visuals.dark_mode;
        if self.last_dark_mode != Some(is_dark) {
            apply_theme_overrides(ctx, is_dark);
            self.last_dark_mode = Some(is_dark);
        }

        // Clear old status messages after 4 seconds
        if let Some(t) = self.status_time {
            if t.elapsed().as_secs() >= 4 {
                self.status_message = None;
                self.status_time = None;
            }
        }

        // --- TOP PANEL ---
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("🔑 MSN Chat NTLM Vault Manager");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄 Reload Vault").clicked() {
                        self.reload_vault();
                        self.show_status("Vault reloaded from disk.".to_string(), true);
                    }
                    ui.label(format!("Total Users: {}", self.users.len()));
                    ui.separator();
                    if self.master_key.is_some() {
                        ui.colored_label(egui::Color32::from_rgb(50, 200, 50), "🟢 Master Key: Loaded");
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(200, 50, 50), "🔴 Master Key: Unloaded");
                    }
                });
            });
            ui.add_space(8.0);
        });

        // --- STATUS & CONFIRMATION BANNERS ---
        if self.status_message.is_some() || self.pending_delete.is_some() {
            egui::TopBottomPanel::top("status_banner_panel")
                .frame(egui::Frame::none().fill(ctx.style().visuals.panel_fill))
                .show(ctx, |ui| {
                ui.add_space(4.0);
                
                // Show standard notification banner
                if let Some((ref msg, is_success)) = self.status_message {
                    let banner_color = if is_success && ui.visuals().dark_mode {
                        egui::Color32::from_rgb(30, 100, 30)
                    } else if is_success {
                        egui::Color32::from_rgb(196, 240, 196)
                    } else if ui.visuals().dark_mode {
                        egui::Color32::from_rgb(100, 30, 30)
                    } else {
                        egui::Color32::from_rgb(248, 210, 210)
                    };
                    let text_color = if ui.visuals().dark_mode {
                        egui::Color32::WHITE
                    } else {
                        egui::Color32::BLACK
                    };
                    
                    ui.add(egui::Button::new(egui::RichText::new(msg).color(text_color))
                        .fill(banner_color)
                        .stroke(egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color))
                    );
                }

                // Show dynamic delete confirmation banner
                let mut to_delete = None;
                let mut clear_delete = false;
                if let Some(ref username) = self.pending_delete {
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            if ui.visuals().dark_mode {
                                egui::Color32::from_rgb(220, 160, 50)
                            } else {
                                egui::Color32::from_rgb(140, 95, 10)
                            },
                            format!("⚠ Are you absolutely sure you want to delete user '{}'?", username)
                        );
                        if ui.button("🗑 Yes, Delete").clicked() {
                            to_delete = Some(username.clone());
                        }
                        if ui.button("Cancel").clicked() {
                            clear_delete = true;
                        }
                    });
                }
                if let Some(uname) = to_delete {
                    self.handle_delete(uname);
                    self.pending_delete = None;
                }
                if clear_delete {
                    self.pending_delete = None;
                }
                
                ui.add_space(4.0);
            });
        }

        // --- CENTRAL SPLIT PANEL ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                
                // === LEFT COLUMN: USER LIST TABLE ===
                columns[0].vertical(|ui| {
                    ui.heading("👤 Registered Accounts");
                    ui.add_space(6.0);
                    
                    let mut sorted_users: Vec<(String, VaultAccount)> = self.users.clone().into_iter().collect();
                    sorted_users.sort_by(|a, b| a.0.cmp(&b.0));

                    if sorted_users.is_empty() {
                        ui.add_space(20.0);
                        ui.colored_label(
                            ui.visuals().weak_text_color(),
                            "No registered users in the database.\nUse the panel on the right to provision accounts.",
                        );
                    } else {
                        egui::ScrollArea::vertical().max_height(480.0).show(ui, |ui| {
                            egui::Grid::new("users_grid")
                                .num_columns(4)
                                .spacing([12.0, 8.0])
                                .striped(true)
                                .show(ui, |ui| {
                                    // Grid Header
                                    ui.label(egui::RichText::new("Username").strong());
                                    ui.label(egui::RichText::new("Domain").strong());
                                    ui.label(egui::RichText::new("Level").strong());
                                    ui.label(egui::RichText::new("Actions").strong());
                                    ui.end_row();

                                    // Grid Rows
                                    for (username, account) in sorted_users {
                                        ui.label(&account.username);
                                        
                                        if account.domain.is_empty() {
                                            ui.colored_label(ui.visuals().weak_text_color(), "[no domain]");
                                        } else {
                                            ui.label(&account.domain);
                                        }

                                        // Role level color-coded badges
                                        match account.level {
                                            UserLevel::Admin => {
                                                ui.add(egui::Label::new(
                                                    egui::RichText::new(" Admin ")
                                                        .color(egui::Color32::WHITE)
                                                        .background_color(egui::Color32::from_rgb(180, 50, 50))
                                                ));
                                            }
                                            UserLevel::Sysop => {
                                                ui.add(egui::Label::new(
                                                    egui::RichText::new(" Sysop ")
                                                        .color(egui::Color32::WHITE)
                                                        .background_color(egui::Color32::from_rgb(46, 115, 230))
                                                ));
                                            }
                                            UserLevel::Guide => {
                                                ui.add(egui::Label::new(
                                                    egui::RichText::new(" Guide ")
                                                        .color(egui::Color32::WHITE)
                                                        .background_color(egui::Color32::from_rgb(50, 150, 50))
                                                ));
                                            }
                                        }

                                        // Actions column
                                        ui.horizontal(|ui| {
                                            if ui.small_button("✏ Edit").clicked() {
                                                self.editing_username = Some(username.clone());
                                                self.input_username = account.username.clone();
                                                self.input_password.clear();
                                                self.input_domain = account.domain.clone();
                                                self.input_level = account.level;
                                            }
                                            if ui.small_button("🗑 Delete").clicked() {
                                                self.pending_delete = Some(username.clone());
                                            }
                                        });
                                        ui.end_row();
                                    }
                                });
                        });
                    }
                });

                // === RIGHT COLUMN: ADD / EDIT ACCOUNT FORM ===
                columns[1].vertical(|ui| {
                    let is_edit = self.editing_username.is_some();
                    if is_edit {
                        ui.heading("✏ Edit User Profile");
                    } else {
                        ui.heading("➕ Register New Account");
                    }
                    ui.add_space(8.0);

                    egui::Frame::none()
                        .fill(ui.visuals().widgets.noninteractive.weak_bg_fill)
                        .rounding(8.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            
                            // Username Input Field
                            ui.label("Username");
                            if is_edit {
                                ui.horizontal(|ui| {
                                    ui.add(egui::TextEdit::singleline(&mut self.input_username)
                                        .desired_width(f32::INFINITY)
                                        .interactive(false)
                                    );
                                });
                                ui.colored_label(ui.visuals().weak_text_color(), "Username is immutable post-creation.");
                            } else {
                                ui.text_edit_singleline(&mut self.input_username);
                            }
                            ui.add_space(6.0);

                            // Password Input Field
                            ui.label("Password");
                            ui.horizontal(|ui| {
                                let mut text_edit = egui::TextEdit::singleline(&mut self.input_password)
                                    .password(!self.show_password)
                                    .desired_width(200.0);
                                    
                                if is_edit {
                                    text_edit = text_edit.hint_text("[Unchanged]");
                                } else {
                                    text_edit = text_edit.hint_text("Enter secure password");
                                }
                                
                                ui.add(text_edit);
                                ui.checkbox(&mut self.show_password, "Show");
                            });
                            if is_edit {
                                ui.colored_label(ui.visuals().weak_text_color(), "Leave empty to keep existing password.");
                            }
                            ui.add_space(6.0);

                            // Domain Input Field
                            ui.label("Domain");
                            ui.text_edit_singleline(&mut self.input_domain);
                            ui.colored_label(ui.visuals().weak_text_color(), "Empty, \".\", or \"workgroup\" mapped to no domain.");
                            ui.add_space(6.0);

                            // User Level Radio Buttons
                            ui.label("User Level");
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut self.input_level, UserLevel::Guide, "Guide");
                                ui.radio_value(&mut self.input_level, UserLevel::Sysop, "Sysop");
                                ui.radio_value(&mut self.input_level, UserLevel::Admin, "Admin");
                            });
                            ui.add_space(12.0);

                            // Actions
                            ui.horizontal(|ui| {
                                let save_btn_text = if is_edit { "Save Changes" } else { "Create User" };
                                if ui.button(save_btn_text).clicked() {
                                    self.handle_save();
                                }
                                
                                if is_edit {
                                    if ui.button("Cancel").clicked() {
                                        self.reset_form();
                                    }
                                } else {
                                    if ui.button("Clear Form").clicked() {
                                        self.reset_form();
                                    }
                                }
                            });
                        });
                });
            });
        });
    }
}
