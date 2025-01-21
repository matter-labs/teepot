# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, inputs
, makeRustPlatform
, nixsgx
, pkg-config
, rust-bin
, pkgs
, openssl
}:
let
  rustVersion = rust-bin.fromRustupToolchainFile (inputs.src + "/rust-toolchain.toml");
  rustPlatform = makeRustPlatform {
    cargo = rustVersion;
    rustc = rustVersion;
  };
  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustVersion;
  commonArgs = {
    nativeBuildInputs = [
      pkg-config
      rustPlatform.bindgenHook
    ];

    buildInputs = [
      openssl
      nixsgx.sgx-sdk
      nixsgx.sgx-dcap
      nixsgx.sgx-dcap.quote_verify
      nixsgx.sgx-dcap.libtdx_attest
    ];

    strictDeps = true;

    src = with lib.fileset; toSource {
      root = inputs.src;
      fileset = unions [
        # Default files from crane (Rust and cargo files)
        (craneLib.fileset.commonCargoSources inputs.src)
        (fileFilter (file: file.hasExt "hcl") (inputs.src + "/bin"))
        # deny.toml and friends
        (fileFilter (file: file.hasExt "toml") inputs.src)
        # Custom test data files
        (maybeMissing (inputs.src + "/crates/teepot/tests/data"))
      ];
    };

    checkType = "debug";
    env = {
      OPENSSL_NO_VENDOR = "1";
      NIX_OUTPATH_USED_AS_RANDOM_SEED = "aaaaaaaaaa";
    };
  };

  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
    pname = "teepot-workspace";
  });
in
{
  inherit rustPlatform
    rustVersion
    commonArgs
    craneLib
    cargoArtifacts;
}
