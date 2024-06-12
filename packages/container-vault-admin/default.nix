# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, nixsgx
, teepot
, buildEnv
, curl
}:
dockerTools.buildLayeredImage {
  name = "vault-unseal";

  config.Entrypoint = [ "${teepot.teepot.vault_unseal}/bin/vault-unseal" ];

  contents = buildEnv {
    name = "image-root";
    paths = with dockerTools; with nixsgx;[
      azure-dcap-client
      curl.out
      sgx-dcap.quote_verify
      usrBinEnv
      binSh
      caCertificates
      fakeNss
      teepot.teepot.vault_unseal
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" ];
  };
}
