fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        embed_resource::compile("app.rc");
    }
    println!("cargo:rustc-link-arg=/STACK:8388608");
    tauri_build::build()
}
