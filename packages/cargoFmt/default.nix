# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, inputs
, makeRustPlatform
, nixsgx
, pkg-config
, rust-bin
, pkgs
, callPackage
, ...
}@args:
let
  teepotCrate = import ../teepot/teepot.nix args;
in
teepotCrate.craneLib.cargoFmt (
  teepotCrate.commonArgs // {
    pname = "teepot";
  }
)
