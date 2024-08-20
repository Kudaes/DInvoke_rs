fn main() {
    if cfg!(feature = "syscall") {
        cc::Build::new()
            .file("src/gateway.asm")
            .compile("gateway"); 
    }
}
