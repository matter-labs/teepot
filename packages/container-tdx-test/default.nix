# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, openssl
, curl
, dockerTools
, buildEnv
, teepot
, nixsgx
}:
dockerTools.buildLayeredImage {
  name = "tdx-test";

  config.Entrypoint = [ "${teepot.teepot.tdx_test}/bin/tdx-test-dcap" ];
  config.Env = [
    "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
  ];

  contents = buildEnv {
    name = "image-root";

    paths = with dockerTools;[
      teepot.teepot.tdx_test
      openssl.out
      curl.out
      nixsgx.sgx-dcap.quote_verify
      nixsgx.sgx-dcap.default_qpl
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" ];
  };
}
