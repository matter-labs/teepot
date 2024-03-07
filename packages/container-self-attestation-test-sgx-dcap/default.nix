# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ pkgs
, vat
, nixsgx
, curl
, teepot
, bash
, coreutils
, openssl
}:
let manifest = ./tee-self-attestation-test.manifest.toml;
in pkgs.dockerTools.buildLayeredImage {
  name = "teepot-self-attestation-test-sgx-dcap";
  tag = "base";

  config.Entrypoint = [ "/bin/sh" "-c" ];

  contents = pkgs.buildEnv {
    name = "image-root";

    paths = with pkgs.dockerTools; with nixsgx;[
      bash
      coreutils
      openssl.out
      curl.out
      teepot.teepot.tee_self_attestation_test
      gramine
      restart-aesmd
      sgx-dcap.quote_verify
      sgx-dcap.default_qpl
      sgx-psw
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" "/app" ];
    postBuild = ''
      mkdir -p $out/{app,etc}
      mkdir -p $out/app/{.dcap-qcnl,.az-dcap-client}
      mkdir -p $out/var/run
      mkdir -p $out/${nixsgx.sgx-psw.out}/aesm/
      ln -s ${curl.out}/lib/libcurl.so $out/${nixsgx.sgx-psw.out}/aesm/
      cp ${manifest} $out/app/tee-self-attestation-test.manifest.toml
      printf "precedence ::ffff:0:0/96  100\n" > $out/etc/gai.conf
    '';
  };
}
