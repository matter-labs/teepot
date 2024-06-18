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
, ...
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
      nixsgx.sgx-sdk
      nixsgx.sgx-dcap
      nixsgx.sgx-dcap.quote_verify
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
  };
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
    pname = "teepot-workspace";
    inherit NIX_OUTPATH_USED_AS_RANDOM_SEED;
  });
  NIX_OUTPATH_USED_AS_RANDOM_SEED = "aaaaaaaaaa";
in
{
  inherit rustPlatform
    rustVersion
    commonArgs
    craneLib
    cargoArtifacts;
  NIX_OUTPATH_USED_AS_RANDOM_SEED = "aaaaaaaaaa";
}
