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
let manifest = ./vault.manifest.toml;
in pkgs.dockerTools.buildLayeredImage {
  name = "teepot-vault-sgx-azure";
  tag = "base";

  config.Entrypoint = [ "/bin/sh" "-c" ];

  contents = pkgs.buildEnv {
    name = "image-root";

    paths = with pkgs.dockerTools; with nixsgx;[
      bash
      coreutils
      teepot.teepot.tee_ratls_preexec
      vault
      azure-dcap-client
      openssl.out
      curl.out
      vat.vault-auth-tee
      gramine
      restart-aesmd
      sgx-dcap.quote_verify
      sgx-psw
      usrBinEnv
      binSh
      caCertificates
      fakeNss
      teepot.container-vault-start-config
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/opt/vault" ];
    postBuild = ''
      mkdir -p $out/var/run
      mkdir -p $out/${nixsgx.sgx-psw.out}/aesm/
      mkdir -p $out/opt/vault/data $out/opt/vault/.cache $out/opt/vault/tls
      ln -s ${curl.out}/lib/libcurl.so $out/${nixsgx.sgx-psw.out}/aesm/
      ln -s ${nixsgx.azure-dcap-client.out}/lib/libdcap_quoteprov.so $out/${nixsgx.sgx-psw.out}/aesm/libdcap_quoteprov.so.1
      mkdir -p $out/opt/vault/plugins
      ln -s ${vat.vault-auth-tee}/bin/vault-auth-tee $out/opt/vault/plugins
      cp ${manifest} $out/opt/vault/vault.manifest.toml
    '';
  };
}
