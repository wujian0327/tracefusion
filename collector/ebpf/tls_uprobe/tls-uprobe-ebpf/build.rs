fn main() {
    println!("cargo:rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\"))");
    if which::which("bpf-linker").is_err() {
        panic!("bpf-linker is required to build the eBPF program");
    }
}
