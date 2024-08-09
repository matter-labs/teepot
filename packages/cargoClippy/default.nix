# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepotCrate }: teepotCrate.craneLib.cargoClippy (
  teepotCrate.commonArgs // {
    pname = "teepot";
    inherit (teepotCrate) cargoArtifacts;
  }
)
