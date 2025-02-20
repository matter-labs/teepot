{ lib
, modulesPath
, pkgs
, ...
}: {
  virtualisation.docker.enable = true;

  systemd.services.docker_start_container = {
    description = "The main application container";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "docker.service" "vector.service" "chronyd.service" "metadata.service" ];
    requires = [ "network-online.target" "docker.service" "vector.service" "metadata.service" ];
    serviceConfig = {
      Type = "exec";
      User = "root";
      EnvironmentFile = "-/run/env/env";
    };
    path = [ pkgs.docker pkgs.teepot.teepot.tdx_extend ];
    script = ''
      set -eu -o pipefail

      DIGEST=''${CONTAINER_DIGEST#sha256:}
      echo "Measuring $DIGEST" >&2
      test -c /dev/tdx_guest && tdx-extend --digest "$DIGEST" --rtmr 3

      # /sys/kernel/config is needed for attestation
      docker run -d --rm \
        --name tdx_container \
        --env "GOOGLE_METADATA=1" \
        --network=host \
        --init \
        --privileged \
        -v /sys/kernel/config:/sys/kernel/config \
        "sha256:$DIGEST"
      exec docker wait tdx_container
    '';

    postStop = lib.mkDefault ''
      shutdown --reboot +5
    '';
  };
}
