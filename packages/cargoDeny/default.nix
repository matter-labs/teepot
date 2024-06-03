# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepotCrate }: teepotCrate.craneLib.cargoDeny (
  teepotCrate.commonArgs // {
    pname = "teepot";
  }
)
