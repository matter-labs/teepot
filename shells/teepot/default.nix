# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, pkgs
, mkShell
, teepot
, nixsgx
, stdenv
,
}:
let
  toolchain_with_src = (
    teepot.teepot.passthru.rustVersion.override {
      extensions = [
        "rustfmt"
        "clippy"
        "rust-src"
      ];
    }
  );
in
mkShell {
  inputsFrom = [ teepot.teepot ];

  nativeBuildInputs = with pkgs; [
    toolchain_with_src
    pkg-config
    teepot.teepot.passthru.rustPlatform.bindgenHook
  ];

  packages =
    with pkgs;
    [
      dive
      taplo
      vault
      cargo-release
      azure-cli
      kubectl
      kubectx
      k9s
      google-cloud-sdk
    ];

  env = {
    QCNL_CONF_PATH =
      if (stdenv.hostPlatform.system != "x86_64-linux") then
        ""
      else
        "${nixsgx.sgx-dcap.default_qpl}/etc/sgx_default_qcnl.conf";
    OPENSSL_NO_VENDOR = "1";
    RUST_SRC_PATH = "${toolchain_with_src}/lib/rustlib/src/rust/";
  };

  shellHook = ''
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${
      pkgs.lib.makeLibraryPath (lib.optionals (stdenv.hostPlatform.system == "x86_64-linux") [
        pkgs.curl
        nixsgx.sgx-dcap
        nixsgx.sgx-dcap.quote_verify
        nixsgx.sgx-dcap.default_qpl
      ])}"
  '';
}
