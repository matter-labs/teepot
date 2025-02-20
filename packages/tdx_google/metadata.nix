{ lib
, modulesPath
, pkgs
, ...
}: {
  systemd.services.metadata = {
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    enable = true;
    path = [ pkgs.curl pkgs.docker pkgs.teepot.teepot.tdx_extend pkgs.coreutils ];
    wantedBy = [ "default.target" ];
    after = [ "network-online.target" "docker.service" ];
    requires = [ "network-online.target" "docker.service" ];
    script = ''
      set -eu -o pipefail
      : "''${CONTAINER_HUB:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_hub" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_IMAGE:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_image" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_TOKEN:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_token" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_USER:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_user" -H "Metadata-Flavor: Google")}"
      : "''${HOST_ID:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/id" -H "Metadata-Flavor: Google")}"
      : "''${HOST_IMAGE:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google")}"
      : "''${HOST_NAME:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/hostname" -H "Metadata-Flavor: Google")}"
      : "''${KAFKA_TOPIC:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kafka_topic" -H "Metadata-Flavor: Google")}"
      : "''${KAFKA_URLS:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kafka_urls" -H "Metadata-Flavor: Google")}"

      : "''${CONTAINER_IMAGE:?Error: Missing CONTAINER_IMAGE}"
      : "''${CONTAINER_HUB:?Error: Missing CONTAINER_HUB}"

      if [[ $CONTAINER_USER ]] && [[ $CONTAINER_TOKEN ]]; then
        docker login -u "$CONTAINER_USER" -p "$CONTAINER_TOKEN" "$CONTAINER_HUB"
      fi

      docker pull "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}"
      CONTAINER_DIGEST=$(docker inspect --format '{{.Id}}' "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}")

      mkdir -p /run/env
      cat >/run/env/env <<EOF
      CONTAINER_HUB="''${CONTAINER_HUB}"
      CONTAINER_IMAGE="''${CONTAINER_IMAGE}"
      CONTAINER_TOKEN="''${CONTAINER_TOKEN}"
      CONTAINER_USER="''${CONTAINER_USER}"
      CONTAINER_DIGEST="''${CONTAINER_DIGEST}"
      HOST_ID="''${HOST_ID}"
      HOST_IMAGE="''${HOST_IMAGE}"
      HOST_NAME="''${HOST_NAME}"
      KAFKA_TOPIC="''${KAFKA_TOPIC}"
      KAFKA_URLS="''${KAFKA_URLS}"
      EOF
    '';
    postStop = lib.mkDefault ''
      shutdown --reboot +5
    '';
  };
}
