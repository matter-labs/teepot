{ lib
, dockerTools
, teepot
, ...
}:
dockerTools.buildImage {
  name = "verify-attestation";
  copyToRoot = [
    teepot.teepot.verify_attestation
  ];
  config = { Cmd = [ "${teepot.teepot.verify_attestation}/bin/verify-attestation" ]; };
}
