# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepot }: teepot.teepot.passthru.craneLib.cargoClippy (
  teepot.teepot.passthru.commonArgs // {
    pname = "teepot";
    inherit (teepot.teepot.passthru) cargoArtifacts;
  }
)
