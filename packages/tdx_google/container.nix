{ lib
, modulesPath
, pkgs
, ...
}: {
  virtualisation.docker.enable = true;

  systemd.services.docker_start_container = {
    description = "The main application container";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "docker.service" "vector.service" "chronyd.service" ];
    requires = [ "network-online.target" "docker.service" "vector.service" ];
    serviceConfig = {
      Type = "exec";
      User = "root";
      EnvironmentFile = "-/run/container/env";
      ExecStartPre = "+" + toString (
        pkgs.writeShellScript "container-start-pre" ''
          set -eu -o pipefail
          : "''${CONTAINER_IMAGE:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_image" -H "Metadata-Flavor: Google")}"
          : "''${CONTAINER_HUB:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_hub" -H "Metadata-Flavor: Google")}"
          : "''${CONTAINER_USER:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_user" -H "Metadata-Flavor: Google")}"
          : "''${CONTAINER_TOKEN:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_token" -H "Metadata-Flavor: Google")}"

          : "''${CONTAINER_IMAGE:?Error: Missing CONTAINER_IMAGE}"
          : "''${CONTAINER_HUB:?Error: Missing CONTAINER_HUB}"

          mkdir -p /run/container
          cat >/run/container/env <<EOF
          CONTAINER_IMAGE="''${CONTAINER_IMAGE}"
          CONTAINER_HUB="''${CONTAINER_HUB}"
          CONTAINER_USER="''${CONTAINER_USER}"
          CONTAINER_TOKEN="''${CONTAINER_TOKEN}"
          EOF
        ''
      );
    };
    path = [ pkgs.curl pkgs.docker pkgs.teepot.teepot.tdx_extend pkgs.coreutils ];
    script = ''
      set -eu -o pipefail
      if [[ $CONTAINER_USER ]] && [[ $CONTAINER_TOKEN ]]; then
        docker login -u "$CONTAINER_USER" -p "$CONTAINER_TOKEN" "$CONTAINER_HUB"
      fi

      docker pull "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}"
      DIGEST=$(docker inspect --format '{{.Id}}' "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}")
      DIGEST=''${DIGEST#sha256:}
      echo "Measuring $DIGEST" >&2
      test -c /dev/tdx_guest && tdx-extend --digest "$DIGEST" --rtmr 3
      exec docker run --env "GOOGLE_METADATA=1" --network=host --init --privileged "sha256:$DIGEST"
    '';

    postStop = lib.mkDefault ''
      shutdown --reboot +5
    '';
  };
}
