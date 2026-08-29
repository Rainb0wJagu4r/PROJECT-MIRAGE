pub mod commands;

use commands::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            pick_file,
            pick_files,
            get_file_info,
            assess_password,
            run_kats,
            encrypt_file_tauri,
            decrypt_file_tauri,
            shamir_split_tauri
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
