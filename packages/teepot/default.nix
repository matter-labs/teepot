# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ teepotCrate }: teepotCrate.craneLib.buildPackage (
  teepotCrate.commonArgs // {
    pname = "teepot";
    inherit (teepotCrate) cargoArtifacts
      NIX_OUTPATH_USED_AS_RANDOM_SEED;


    passthru = {
      inherit (teepotCrate) rustPlatform
        rustVersion
        commonArgs
        craneLib
        cargoArtifacts;
      NIX_OUTPATH_USED_AS_RANDOM_SEED = "aaaaaaaaaa";
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
    ];
    postInstall = ''
      removeReferencesToVendoredSources "$out" "$cargoVendorDir"
      mkdir -p $out/nix-support
      for i in $outputs; do
        [[ $i == "out" ]] && continue
        mkdir -p "''${!i}/bin"
        echo "''${!i}" >> $out/nix-support/propagated-user-env-packages
        binname=''${i//_/-}
        mv "$out/bin/$binname" "''${!i}/bin/"
      done
    '';
  }
)

