# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, inputs
, makeRustPlatform
, nixsgx
, pkg-config
, rust-bin
, pkgs
, src
, openssl
}:
let
  rustVersion = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
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
      root = src;
      fileset = unions [
        ./Cargo.lock
        ./Cargo.toml
        ./bin
        ./crates
        ./rust-toolchain.toml
        ./deny.toml
        ./taplo.toml
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
