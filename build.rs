// LogCrab - GPL-3.0-or-later
// Build script: embed version info and compile protobuf definitions.

use std::process::Command;

fn main() {
    // ── Compile proto definitions ─────────────────────────────────────────────
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false) // server lives in the Python sidecar
        .compile_protos(&["proto/sidecar_v2.proto"], &["proto"])
        .expect("failed to compile sidecar_v2.proto");

    println!("cargo:rerun-if-changed=proto/sidecar_v2.proto");

    // ── Embed git version info ────────────────────────────────────────────────
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());

    // Check if working directory is dirty
    let is_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .is_ok_and(|output| !output.stdout.is_empty());

    let git_hash = if is_dirty {
        format!("{git_hash}-dirty")
    } else {
        git_hash
    };

    println!("cargo:rustc-env=GIT_HASH={git_hash}");

    // Rerun if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
