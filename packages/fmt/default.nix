# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, pkgs
, teepot
, ...
}:
pkgs.writeShellApplication {
  name = "fmt-teepot";

  runtimeInputs = with pkgs;
    [ nixpkgs-fmt coreutils taplo ]
    ++ teepot.teepot.nativeBuildInputs;

  text = ''
    # .nix
    echo "* Formatting nix files"
    nixpkgs-fmt .

    # .toml
    echo "* Formatting toml files"
    taplo fmt

    # .rs
    echo "* Formatting rust files"
    cargo fmt
  '';
}
