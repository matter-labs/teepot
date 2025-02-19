{ lib
, modulesPath
, pkgs
, ...
}: {
  services.vector.enable = true;
  services.vector.settings = {
    api.enabled = false;
    sources = {
      otlp = {
        type = "opentelemetry";
        grpc = { address = "127.0.0.1:4317"; };
        http = {
          address = "127.0.0.1:4318";
          keepalive = {
            max_connection_age_jitter_factor = 0.1;
            max_connection_age_secs = 300;
          };
        };
      };
    };
    sinks = {
      console = {
        inputs = [ "otlp.logs" ];
        target = "stdout";
        type = "console";
        encoding = { codec = "json"; };
      };
      kafka = {
        type = "kafka";
        inputs = [ "otlp.logs" ];
        bootstrap_servers = "\${KAFKA_URLS:-127.0.0.1:0}";
        topic = "\${KAFKA_TOPIC:-tdx-google}";
        encoding = {
          codec = "json";
          compression = "lz4";
        };
      };
    };
  };
  systemd.services.vector.path = [ pkgs.curl pkgs.coreutils ];
  # `-` means, that the file can be missing, so that `ExecStartPre` can execute and create it
  systemd.services.vector.serviceConfig.EnvironmentFile = "-/run/vector/env";
  # `+` means, that the process has access to all files, to be able to write to `/run`
  systemd.services.vector.serviceConfig.ExecStartPre = "+" + toString (
    pkgs.writeShellScript "vector-start-pre" ''
      set -eu -o pipefail
      : "''${KAFKA_URLS:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kafka_urls" -H "Metadata-Flavor: Google")}"
      : "''${KAFKA_TOPIC:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kafka_topic" -H "Metadata-Flavor: Google")}"

      KAFKA_TOPIC="''${KAFKA_TOPIC:-tdx-google}"

      mkdir -p /run/vector
      cat >/run/vector/env <<EOF
      KAFKA_URLS="''${KAFKA_URLS}"
      KAFKA_TOPIC="''${KAFKA_TOPIC}"
      EOF
    ''
  );
}
