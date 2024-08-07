# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, mkShell
, teepot
, dive
, taplo
, vault
}:
mkShell {
  inputsFrom = [ teepot.teepot ];
  packages = [
    dive
    taplo
    vault
  ];
}
