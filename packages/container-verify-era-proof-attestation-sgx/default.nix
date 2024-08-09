# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, buildEnv
, teepot
, openssl
, curl
, nixsgx
, pkg-config
}:
dockerTools.buildLayeredImage {
  name = "verify-era-proof-attestation";

  config.Entrypoint = [ "${teepot.teepot.verify_era_proof_attestation}/bin/verify-era-proof-attestation" ];
  config.Env = [ "LD_LIBRARY_PATH=/lib" ];
  contents = buildEnv {
    name = "image-root";

    paths = with dockerTools; with nixsgx;[
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
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" ];
  };
}
