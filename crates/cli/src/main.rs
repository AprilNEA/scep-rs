//! `scep` command line: `getcacaps`, `getcacert`, `enroll`, and `serve`, a
//! file-backed test CA.
//!
//! This release reserves the crate name. The binary only reports that. The first
//! usable release is `0.1.0`; the design and progress live in
//! <https://github.com/AprilNEA/scep-rs>.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "scep-cli {} reserves the crate name and has no commands yet; see https://github.com/AprilNEA/scep-rs",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
