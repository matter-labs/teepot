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
  name = "verify-rpc-attestation-sgx";

  config.Entrypoint = [ "${teepot.teepot.verify_rpc_attestation}/bin/verify-rpc-attestation" ];
  config.Env = [ "LD_LIBRARY_PATH=/lib" ];
  contents = buildEnv {
    name = "image-root";

    paths = with dockerTools; with nixsgx;[
      openssl.out
      curl.out
      sgx-dcap.quote_verify
      sgx-dcap.default_qpl
      teepot.teepot.verify_rpc_attestation
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" ];
  };
}
