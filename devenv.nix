{ pkgs, ... }:

{
  packages = [ pkgs.cargo-deny pkgs.openssl pkgs.actionlint ];

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.99.1";
    components = [ "rustc" "cargo" "clippy" "rustfmt" ];
  };

  scripts.check.exec = ''
    set -euo pipefail
    actionlint .github/workflows/*.yml
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --all-features --locked
    cargo test --workspace --all-features --locked
    cargo deny check
  '';

  enterTest = "check";
}
