# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, buildEnv
, teepot
, stdenv
, openssl
, curl
, nixsgx
, pkg-config
}:
if (stdenv.hostPlatform.isDarwin) then {
  # FIXME: dockerTools.buildLayeredImage seems to be broken on Darwin
} else
  dockerTools.buildLayeredImage {
    name = "verify-era-proof-attestation";

    config.Entrypoint = [
      "${teepot.teepot.verify_era_proof_attestation}/bin/verify-era-proof-attestation"
    ];
    config.Env = [ "LD_LIBRARY_PATH=/lib" ];
    contents = buildEnv {
      name = "image-root";

      paths =
        with dockerTools;
        with nixsgx;
        [
          pkg-config
          openssl.out
          curl.out
          sgx-dcap.quote_verify
          sgx-dcap.default_qpl
          teepot.teepot.verify_era_proof_attestation
          usrBinEnv
          binSh
          caCertificates
          fakeNss
        ];
      pathsToLink = [
        "/bin"
        "/lib"
        "/etc"
        "/share"
      ];
    };
  }
