fn main() {
    //static_vcruntime::metabuild();
    //println!("cargo:rustc-link-lib=kernel32");
    cc::Build::new()
    .file("src/gateway.asm")
    .compile("gateway"); 
}