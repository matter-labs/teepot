# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepot
, pkgs
, stdenv
, bash
, coreutils
, container-name ? "teepot-key-preexec-dcap"
, tag ? null
}: let
  entrypoint = "${bash}/bin/bash";
in
if (stdenv.hostPlatform.system != "x86_64-linux") then { } else
pkgs.lib.tee.sgxGramineContainer {
  name = container-name;
  inherit tag entrypoint;

  packages = [ teepot.teepot.tee_key_preexec coreutils bash ];

  manifest = {
    loader = {
      argv = [
        entrypoint
        "-c"
        ("${teepot.teepot.tee_key_preexec}/bin/tee-key-preexec -- bash -c "
        + "'echo \"SIGNING_KEY=$SIGNING_KEY\"; echo \"TEE_TYPE=$TEE_TYPE\";exec base64 \"$ATTESTATION_QUOTE_FILE_PATH\";'")
      ];

      log_level = "error";
      env = {
        RUST_BACKTRACE = "1";
        RUST_LOG = "trace";
      };
    };
    sgx = {
      edmm_enable = true;
      max_threads = 2;
    };
  };
}
