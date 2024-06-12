# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, pkgs
, inputs
, teepot
, nixsgx
, vat
, container-name ? "teepot-vault-unseal-sgx-azure"
, tag ? null
, isAzure ? true
}:
pkgs.callPackage inputs.nixsgx-flake.lib.mkSGXContainer {
  name = container-name;
  inherit tag;

  packages = [
    vat.vault-auth-tee.sha
    teepot.teepot.tee_vault_unseal
  ];
  entrypoint = "${teepot.teepot.tee_vault_unseal}/bin/tee-vault-unseal";

  isAzure = true;

  manifest = {
    loader = {
      log_level = "error";
      env = {
        ### Admin Config ###
        PORT.passthrough = true;

        ### VAULT attestation ###
        VAULT_ADDR.passthrough = true;
        VAULT_SGX_MRENCLAVE.passthrough = true;
        VAULT_SGX_MRSIGNER.passthrough = true;
        VAULT_SGX_ALLOWED_TCB_LEVELS.passthrough = true;

        ### DEBUG ###
        RUST_BACKTRACE = "1";
        RUST_LOG = "info,tee_vault_unseal=trace,teepot=trace,vault_tee_client=trace,tee_client=trace,awc=debug";

        ### Enclave security ###
        ALLOWED_TCB_LEVELS = "SwHardeningNeeded";

        VAULT_AUTH_TEE_SHA256 = "${vat.vault-auth-tee.sha}/share/vault-auth-tee.sha256";
      };
    };

    sgx = {
      edmm_enable = false;
      enclave_size = "2G";
      max_threads = 64;
    };

    # possible tweak option, if problems with mio
    # currently mio is compiled with `mio_unsupported_force_waker_pipe`
    # sys.insecure__allow_eventfd = true
  };
}
