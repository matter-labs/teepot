# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, dockerTools
, teepot
, ...
}:
dockerTools.buildImage {
  name = "verify-attestation";
  tag = "latest";

  copyToRoot = [
    teepot.teepot.verify_attestation
  ];
  config = { Cmd = [ "${teepot.teepot.verify_attestation}/bin/verify-attestation" ]; };
}
