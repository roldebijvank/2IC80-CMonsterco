fn main() {
    // Required for libsodium RNG on Windows GNU
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=bcrypt");
}
 