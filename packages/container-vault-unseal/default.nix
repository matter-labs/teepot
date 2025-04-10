# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, lib
, stdenv
, buildEnv
, teepot
, openssl
, curl
, nixsgx
}:
if (stdenv.hostPlatform.isDarwin) then {
  # FIXME: dockerTools.buildLayeredImage seems to be broken on Darwin
} else
  dockerTools.buildLayeredImage {
    name = "vault-unseal";

    config.Entrypoint = [ "${teepot.teepot.vault_unseal}/bin/vault-unseal" ];

    contents = buildEnv {
      name = "image-root";
      paths =
        with dockerTools;
        with nixsgx;
        [
          openssl.out
          curl.out
          usrBinEnv
          binSh
          caCertificates
          fakeNss
          teepot.teepot.vault_unseal
        ] ++ lib.optionals (stdenv.hostPlatform.system == "x86_64-linux") [
          sgx-dcap.quote_verify
          sgx-dcap.default_qpl
        ];
      pathsToLink = [
        "/bin"
        "/lib"
        "/etc"
      ];
    };
  }
