# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepotCrate }: teepotCrate.craneLib.buildPackage (
  teepotCrate.commonArgs // {
    pname = "teepot";
    inherit (teepotCrate) cargoArtifacts;

    passthru = {
      inherit (teepotCrate) rustPlatform
        rustVersion
        commonArgs
        craneLib
        cargoArtifacts;
    };

    outputs = [
      "out"
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
      done
      rmdir "$out/bin"
    '';
  }
)

