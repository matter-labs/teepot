# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, mkShell
, teepot
, dive
, taplo
, vault
, cargo-release
, nixsgx
, stdenv
, teepotCrate
, pkg-config
}:
let
  toolchain_with_src = (teepotCrate.rustVersion.override {
    extensions = [ "rustfmt" "clippy" "rust-src" ];
  });
in
mkShell {
  inputsFrom = [ teepot.teepot ];

  nativeBuildInputs = [
    toolchain_with_src
    pkg-config
    teepotCrate.rustPlatform.bindgenHook
  ];

  packages = [
    dive
    taplo
    vault
    cargo-release
  ];

  TEE_LD_LIBRARY_PATH = lib.makeLibraryPath [
    nixsgx.sgx-dcap
    nixsgx.sgx-dcap.quote_verify
    nixsgx.sgx-dcap.default_qpl
  ];

  QCNL_CONF_PATH = "${nixsgx.sgx-dcap.default_qpl}/etc/sgx_default_qcnl.conf";
  OPENSSL_NO_VENDOR = "1";
  RUST_SRC_PATH = "${toolchain_with_src}/lib/rustlib/src/rust/library";

  shellHook = ''
    if [ "x$NIX_LD" = "x" ]; then
      export NIX_LD=$(<${stdenv.cc}/nix-support/dynamic-linker)
    fi
    if [ "x$NIX_LD_LIBRARY_PATH" = "x" ]; then
      export NIX_LD_LIBRARY_PATH="$TEE_LD_LIBRARY_PATH"
    else
      export NIX_LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH:$TEE_LD_LIBRARY_PATH"
    fi
  '';
}
