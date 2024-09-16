# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, mkShell
, teepot
, dive
, taplo
, vault
, cargo-release
}:
mkShell {
  inputsFrom = [ teepot.teepot ];

  shellHook = ''
    export OPENSSL_NO_VENDOR="1";
  '';

  packages = [
    dive
    taplo
    vault
    cargo-release
  ];
}
