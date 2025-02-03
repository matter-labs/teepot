# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib, pkgs, makeWrapper, teepot }:
let teepotCrate = teepot.teepotCrate; in
teepotCrate.craneLib.buildPackage (
  teepotCrate.commonArgs // {
    pname = "teepot";
    inherit (teepotCrate) cargoArtifacts;

    nativeBuildInputs = teepotCrate.commonArgs.nativeBuildInputs ++ [ makeWrapper ];

    passthru = {
      inherit (teepotCrate) rustPlatform
        rustVersion
        commonArgs
        craneLib
        cargoArtifacts;
    };

    outputs = [
      "out"
      "google_metadata"
      "rtmr_calc"
      "sha384_extend"
      "tdx_extend"
      "tee_key_preexec"
      "tee_ratls_preexec"
      "tee_self_attestation_test"
      "tee_stress_client"
      "tee_vault_admin"
      "tee_vault_unseal"
      "teepot_read"
      "teepot_write"
      "vault_admin"
      "vault_unseal"
      "verify_attestation"
      "verify_era_proof_attestation"
    ];

    postInstall = ''
      removeReferencesToVendoredSources "$out" "$cargoVendorDir"
      removeReferencesToVendoredSources "$out" "${teepotCrate.rustVersion}/lib/rustlib/"
      mkdir -p $out/nix-support
      for i in $outputs; do
        [[ $i == "out" ]] && continue
        mkdir -p "''${!i}/bin"
        echo -n "''${!i} " >> $out/nix-support/propagated-user-env-packages
        binname=''${i//_/-}
        mv "$out/bin/$binname" "''${!i}/bin/"

        makeWrapper "''${!i}/bin/$binname" "''${!i}/bin/$binname-dcap" \
          --prefix LD_LIBRARY_PATH : "${lib.makeLibraryPath [ pkgs.nixsgx.sgx-dcap.quote_verify pkgs.nixsgx.sgx-dcap.default_qpl pkgs.curl ]}" \
          --set-default QCNL_CONF_PATH "${pkgs.nixsgx.sgx-dcap.default_qpl}/etc/sgx_default_qcnl.conf"

      done
      rmdir "$out/bin"
    '';
  }
)

