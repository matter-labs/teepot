# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs

{ lib
, stdenv
}:
stdenv.mkDerivation {
  name = "container-vault-start-config";
  src = with lib.fileset; toSource {
    root = ./.;
    fileset = unions [
      ./cacert.pem
      ./cakey.pem
      ./config.hcl
    ];
  };

  phases = "installPhase";
  postInstall = ''
    mkdir -p $out/opt/vault
    cp -r $src/* $out/opt/vault

    mkdir -p $out/etc
    printf "precedence ::ffff:0:0/96  100\n" > $out/etc/gai.conf
  '';
}
