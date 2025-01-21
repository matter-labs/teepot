# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, pkgs
, mkShell
, teepot
, nixsgx
, stdenv
}:
let
  toolchain_with_src = (teepot.teepot.passthru.rustVersion.override {
    extensions = [ "rustfmt" "clippy" "rust-src" ];
  });
in
mkShell {
  inputsFrom = [ teepot.teepot ];

  nativeBuildInputs = with pkgs; [
    toolchain_with_src
    pkg-config
    teepot.teepot.passthru.rustPlatform.bindgenHook
  ];

  packages = with pkgs; [
    dive
    taplo
    vault
    cargo-release
    google-cloud-sdk-gce
    azure-cli
    kubectl
    kubectx
    k9s
  ];

  TEE_LD_LIBRARY_PATH = lib.makeLibraryPath [
    pkgs.curl
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
