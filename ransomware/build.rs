fn main() {
    // Required for libsodium RNG on Windows GNU
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=bcrypt");
    
    // Embed Windows manifest for Common Controls v6
    embed_resource::compile("app.rc", embed_resource::NONE);
}
 