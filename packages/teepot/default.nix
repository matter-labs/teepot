{ lib
, gccStdenv
, makeRustPlatform
, nixsgx
, pkg-config
, rust-bin
, ...
}:
let
  cargoToml = (builtins.fromTOML (builtins.readFile ../../Cargo.toml));
  rustVersion = rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml;
  rustPlatform = makeRustPlatform {
    cargo = rustVersion;
    rustc = rustVersion;
  };
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  version = cargoToml.workspace.package.version;

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];

  buildInputs = [
    nixsgx.sgx-sdk
    nixsgx.sgx-dcap
    nixsgx.sgx-dcap.quote_verify
  ];

  src = with lib.fileset; toSource {
    root = ./../..;
    fileset = unions [
      ../../Cargo.lock
      ../../Cargo.toml
      ../../assets
      ../../bin
      ../../crates
      ../../rust-toolchain.toml
      ../../src
      ../../tests
    ];
  };
  RUSTFLAGS = "--cfg mio_unsupported_force_waker_pipe";
  cargoBuildFlags = "--all";
  checkType = "debug";
  cargoLock = {
    lockFile = ../../Cargo.lock;
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
}
