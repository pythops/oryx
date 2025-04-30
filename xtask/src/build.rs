use std::{path::Path, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
}

/// Set the ORYX_BIN_PATH env var based on build option
fn set_ebpf_build_base_dir(build_type: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../target/bpfel-unknown-none/{build_type}/oryx"))
        .to_path_buf();
    std::env::set_var("ORYX_BIN_PATH", &path);
}

/// Build the project
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release");
        set_ebpf_build_base_dir("release");
    } else {
        set_ebpf_build_base_dir("debug");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build our ebpf program and the project
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}

/// Run linter on the project with ORYX_BIN_DIR env var set
pub fn lint() -> Result<(), anyhow::Error> {
    set_ebpf_build_base_dir("debug");
    let status = Command::new("cargo")
        .args([
            "clippy",
            "--workspace",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ])
        .status()
        .expect("failed to build userspace");

    assert!(status.success());
    Ok(())
}
