//! Compiles the CryptoKit shim (swift/enclave.swift) into a static library.
//! Secure Enclave keys cannot be persisted via SecKey without a keychain
//! entitlement, so the shim uses CryptoKit's self-contained key blobs instead.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = std::env::var("OUT_DIR").unwrap();
    let src = "swift/enclave.swift";
    println!("cargo:rerun-if-changed={src}");

    let obj = format!("{out}/enclave.o");
    let status = std::process::Command::new("swiftc")
        .args([
            "-O",
            "-parse-as-library",
            "-emit-object",
            "-module-name",
            "enclave_shim",
            "-o",
            &obj,
            src,
        ])
        .status()
        .expect("swiftc not found (install Xcode command line tools)");
    assert!(status.success(), "swiftc failed");

    let lib = format!("{out}/libenclave_shim.a");
    let status = std::process::Command::new("ar")
        .args(["crs", &lib, &obj])
        .status()
        .expect("ar not found");
    assert!(status.success(), "ar failed");

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=enclave_shim");
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for f in ["CryptoKit", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={f}");
    }
}
