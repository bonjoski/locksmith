fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/macos_dock.m")
            .compile("macos_dock");
        println!("cargo:rerun-if-changed=src/macos_dock.m");
    }
    tauri_build::build();
}
