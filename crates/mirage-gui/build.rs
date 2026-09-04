fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        println!("cargo:rerun-if-changed=../../assets/icon.ico");
        println!("cargo:rerun-if-changed=../../assets/nobug.ico");
        println!("cargo:rerun-if-changed=mirage.rc");
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let res_path = format!("{out_dir}/mirage.o");
        let windres = std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".into());
        let status = std::process::Command::new(&windres)
            .args(["-i", "mirage.rc", "-o", &res_path])
            .status();
        if let Ok(s) = status {
            if s.success() {
                println!("cargo:rustc-link-arg={res_path}");
            }
        }
    }
}
