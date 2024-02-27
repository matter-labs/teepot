# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib
, dockerTools
, nixsgx
, teepot
, buildEnv
, curl
, ...
}:
dockerTools.buildLayeredImage {
  name = "vault-unseal";
  tag = "latest";

  config.Entrypoint = [ "${teepot.teepot.vault_unseal}/bin/vault-unseal" ];

  contents = buildEnv {
    name = "image-root";
    paths = with dockerTools; with nixsgx;[
      azure-dcap-client
      curl
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
