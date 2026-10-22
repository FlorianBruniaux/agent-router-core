//! Exposes the compilation target to `version --json`. Cargo sets `TARGET`
//! only for build scripts, so the value is forwarded as a compile-time variable.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=AGENT_ROUTER_TARGET={target}");
}
