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
teepotCrate.craneLib.cargoClippy (
  teepotCrate.commonArgs // {
    pname = "teepot";
    inherit (teepotCrate) cargoArtifacts NIX_OUTPATH_USED_AS_RANDOM_SEED;
  }
)
