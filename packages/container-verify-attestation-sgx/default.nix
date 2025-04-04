# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, buildEnv
, lib
, stdenv
, teepot
, openssl
, curl
, nixsgx
}:
if (stdenv.hostPlatform.isDarwin) then {
  # FIXME: dockerTools.buildLayeredImage seems to be broken on Darwin
} else
  dockerTools.buildLayeredImage {
    name = "verify-attestation-sgx";

    config.Entrypoint = [ "${teepot.teepot.verify_attestation}/bin/verify-attestation" ];
    config.Env = [ "LD_LIBRARY_PATH=/lib" ];
    contents = buildEnv {
      name = "image-root";

      paths =
        with dockerTools;
        with nixsgx;
        [
          openssl.out
          curl.out
          teepot.teepot.verify_attestation
          usrBinEnv
          binSh
          caCertificates
          fakeNss
        ] ++ lib.optionals (stdenv.hostPlatform.system == "x86_64-linux") [
          sgx-dcap.quote_verify
          sgx-dcap.default_qpl
        ];
      pathsToLink = [
        "/bin"
        "/lib"
        "/etc"
        "/share"
      ];
    };
  }
