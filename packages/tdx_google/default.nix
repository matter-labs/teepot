# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, pkgs
, stdenv
, system
, ...
}:
if (stdenv.hostPlatform.system != "x86_64-linux") then { } else
lib.teepot.nixosGenerate {
  inherit (lib) nixosSystem;
  inherit system pkgs;
  modules = [
    ./configuration.nix
    ./google.nix
  ];
  formatModule = ./verity.nix;
}
