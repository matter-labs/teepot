{
  description = "teepot";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    nix-filter.url = "github:numtide/nix-filter";
    flake-utils.url = "github:numtide/flake-utils";

    nixsgx-flake = {
      url = "github:matter-labs/nixsgx";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, nix-filter, nixsgx-flake, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ (import rust-overlay) nixsgx-flake.overlays.default ]; };
        rustVersion = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        makeRustPlatform = pkgs.makeRustPlatform.override {
          stdenv = pkgs.stdenvAdapters.useMoldLinker pkgs.gccStdenv;
        };
        rustPlatform = makeRustPlatform {
          cargo = rustVersion;
          rustc = rustVersion;
        };

        filter = nix-filter.lib;

        bin = rustPlatform.buildRustPackage {
          pname = "teepot";
          version = "0.1.0";

          nativeBuildInputs = with pkgs; [
            pkg-config
            rustPlatform.bindgenHook
          ];

          buildInputs = with pkgs; [
            nixsgx.sgx-sdk
            nixsgx.sgx-dcap
            nixsgx.sgx-dcap.quote_verify
          ];

          src = filter {
            root = ./.;
            exclude = [
              ".github"
              ".gitignore"
              "flake.lock"
              "flake.nix"
              "LICENSE-APACHE"
              "LICENSE-MIT"
              "README.md"
              "renovate.json"
              "deny.toml"
              (filter.inDirectory "examples")
              (filter.inDirectory "vault")
            ];
          };
          RUSTFLAGS = "--cfg mio_unsupported_force_waker_pipe";
          cargoBuildFlags = "--all";
          checkType = "debug";
          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          outputs = [
            "out"
            "tee_key_preexec"
            "tee_self_attestation_test"
            "tee_stress_client"
            "tee_vault_admin"
            "tee_vault_unseal"
            "teepot_read"
            "teepot_write"
            "vault_admin"
            "vault_unseal"
            "verify_attestation"
          ];

          postInstall = ''
            mkdir -p $out/nix-support
            for i in $outputs; do
              [[ $i == "out" ]] && continue
              mkdir -p "''${!i}/bin"
              echo "''${!i}" >> $out/nix-support/propagated-user-env-packages
              binname=''${i//_/-}
              mv "$out/bin/$binname" "''${!i}/bin/"
            done
          '';
        };
      in
      {
        formatter = pkgs.nixpkgs-fmt;

        packages = rec {
          teepot = bin;
          default = teepot;
        };

        devShells = {
          default = pkgs.mkShell {
            inputsFrom = [ bin ];
            nativeBuildInputs = with pkgs; [
              rustup
              rustVersion
            ];
          };
        };
      });
}
