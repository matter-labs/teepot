# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ lib, ... }:
{
  wrap_tdx = pkgs: prg:
    let
      oldExe = lib.getExe prg;
    in
    pkgs.stdenv.mkDerivation {
      pname = "${prg.pname}-tdx-wrapped";
      inherit (prg) version;
      nativeBuildInputs = with pkgs; [ makeWrapper ];

      buildCommand = ''
        mkdir -p $out/bin
        newExe="${oldExe}"
        newExe="$out/bin/''${newExe##*/}"
        makeWrapper "${oldExe}" "$newExe" --inherit-argv0 \
          --prefix LD_LIBRARY_PATH ${lib.makeLibraryPath [ pkgs.nixsgx.sgx-dcap.quote_verify pkgs.nixsgx.sgx-dcap.default_qpl pkgs.curl ]} \
          --set-default QCNL_CONF_PATH "${pkgs.nixsgx.sgx-dcap.default_qpl}/etc/sgx_default_qcnl.conf"
      '';
    };
}
