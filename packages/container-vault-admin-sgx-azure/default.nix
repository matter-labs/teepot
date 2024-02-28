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
, vault
}:
let manifest = ./tee-vault-admin.manifest.toml;
in pkgs.dockerTools.buildLayeredImage {
  name = "teepot-vault-admin-sgx-azure";
  tag = "base";

  config.Entrypoint = [ "/bin/sh" "-c" ];

  contents = pkgs.buildEnv {
    name = "image-root";

    paths = with pkgs.dockerTools; with nixsgx; with teepot;[
      bash
      coreutils
      openssl
      vault
      azure-dcap-client
      curl
      teepot.teepot.tee_vault_admin
      gramine
      restart-aesmd
      sgx-dcap.quote_verify
      sgx-psw
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/app" ];
    postBuild = ''
      mkdir -p $out/{app,etc}
      cp ${manifest} $out/app/tee-vault-admin.manifest.toml
      mkdir -p $out/var/run
      mkdir -p $out/${nixsgx.sgx-psw.out}/aesm/
      touch $out/etc/sgx_default_qcnl.conf
      ln -s ${curl.out}/lib/libcurl.so $out/${nixsgx.sgx-psw.out}/aesm/
      ln -s ${nixsgx.azure-dcap-client.out}/lib/libdcap_quoteprov.so $out/${nixsgx.sgx-psw.out}/aesm/libdcap_quoteprov.so.1
      printf "precedence ::ffff:0:0/96  100\n" > $out/etc/gai.conf
    '';
  };
}
