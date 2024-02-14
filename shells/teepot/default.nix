{ lib
, pkgs
, ...
}:
pkgs.mkShell {
  inputsFrom = [ pkgs.teepot.teepot ];
}
