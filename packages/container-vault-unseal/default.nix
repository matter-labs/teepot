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
  name = "vault-unseal";

  config.Entrypoint = [ "${teepot.teepot.vault_unseal}/bin/vault-unseal" ];

  contents = buildEnv {
    name = "image-root";
    paths = with dockerTools; with nixsgx;[
      openssl.out
      curl.out
      sgx-dcap.quote_verify
      sgx-dcap.default_qpl
      usrBinEnv
      binSh
      caCertificates
      fakeNss
      teepot.teepot.vault_unseal
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" ];
  };
}
