// alphanumeric builder supporting multiple target platforms: Windows, OSX, and Linux

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    if target.contains("windows") { // For Windows
        println!("Building alphanumeric for Windows");

        use winres::WindowsResource;
        let mut res = WindowsResource::new();
        res.set_icon("app_icon.ico");
        res.compile().unwrap();
    } else if target.contains("apple-darwin") { // For OSX
        println!("Building alphanumeric for OSX");

        let target_env = env::var("RUST_TARGET_ENV").unwrap_or_else(|_| "gnu".to_string());

        if target_env != "gnu" && target_env != "msvc" {
            panic!("Target environment must be 'gnu' or 'msvc'");
        }
    } else if target.contains("linux") { // For Linux
        println!("Building alphanumeric for Linux");

        let target_env = env::var("RUST_TARGET_ENV").unwrap_or_else(|_| "gnu".to_string());

        if target_env != "gnu" && target_env != "musl" {
            panic!("Unsupported target environment for Linux");
        }
    } else {
        println!("Build script: Unsupported target platform.");
    }
}
