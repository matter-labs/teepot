# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepot
, pkgs
, stdenv
, container-name ? "teepot-self-attestation-test-sgx-azure"
, tag ? null
, isAzure ? true
}:
if (stdenv.hostPlatform.system != "x86_64-linux") then { } else
pkgs.lib.tee.sgxGramineContainer {
  name = container-name;
  inherit tag;

  packages = [ teepot.teepot.tee_self_attestation_test ];
  entrypoint = "${teepot.teepot.tee_self_attestation_test}/bin/tee-self-attestation-test";

  inherit isAzure;

  manifest = {
    loader = {
      log_level = "error";
      env = {
        RUST_BACKTRACE = "1";
        RUST_LOG = "warning";
      };
    };
    sgx = {
      edmm_enable = false;
      enclave_size = "2G";
      max_threads = 64;
    };
  };
}
