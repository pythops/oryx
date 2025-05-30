use std::env;

fn main() {
    let path = match env::var("PROFILE").unwrap().as_str() {
        "release" => "../../../target/bpfel-unknown-none/release/oryx",
        "debug" => "../../../target/bpfel-unknown-none/debug/oryx",
        _ => panic!("unknown release mode"),
    };

    println!("cargo::rustc-env=ORYX_BIN_PATH={path}");
}
