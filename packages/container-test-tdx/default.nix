# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Matter Labs
{ dockerTools
, buildEnv
, teepot
}:
dockerTools.buildLayeredImage {
  name = "test-tdx";

  config.Entrypoint = [ "${teepot.teepot.google_metadata}/bin/google-metadata" ];
  config.Env = [ "LD_LIBRARY_PATH=/lib" ];
  contents = buildEnv {
    name = "image-root";

    paths = with dockerTools;[
      teepot.teepot.google_metadata
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/lib" "/etc" "/share" ];
  };
}
