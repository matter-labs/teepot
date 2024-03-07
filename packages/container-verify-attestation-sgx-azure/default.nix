# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, buildEnv
, teepot
, openssl
, curl
, nixsgx
}:
dockerTools.buildLayeredImage {
  name = "verify-attestation-sgx-azure";
  tag = "latest";

  config.Cmd = [ "${teepot.teepot.verify_attestation}/bin/verify-attestation" ];
  config.Env = [
    "LD_LIBRARY_PATH=/lib"
    "AZDCAP_DEBUG_LOG_LEVEL=ignore"
    "AZDCAP_COLLATERAL_VERSION=v4"
  ];
  contents = buildEnv {
    name = "image-root";

    paths = with dockerTools; with nixsgx;[
      openssl.out
      curl.out
      azure-dcap-client
      sgx-dcap.quote_verify
      teepot.teepot.verify_attestation
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" ];
  };
}
