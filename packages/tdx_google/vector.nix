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
    transforms = {
      add_custom_fields = {
        type = "remap";
        inputs = [ "otlp.logs" ];
        source = ''
          # Create resources if it doesn't exist
          if !exists(.resources) {
              .resources = {}
          }
          # https://opentelemetry.io/docs/specs/semconv/resource/host/
          .resources.host.name            = "''${HOST_NAME:-hostname}"
          .resources.host.id              = "''${HOST_ID:-hostid}"
          .resources.host.image.name      = "''${HOST_IMAGE:-host_image}"

          # https://opentelemetry.io/docs/specs/semconv/resource/container/
          .resources.container.image.name = "''${CONTAINER_HUB:-container_hub}/''${CONTAINER_IMAGE:-container_image}"
          .resources.container.image.id   = "''${CONTAINER_DIGEST:-container_digest}"
        '';
      };
    };
    sinks = {
      console = {
        inputs = [ "add_custom_fields" ];
        target = "stdout";
        type = "console";
        encoding = { codec = "json"; };
      };
      kafka = {
        type = "kafka";
        inputs = [ "add_custom_fields" ];
        bootstrap_servers = "\${KAFKA_URLS:-127.0.0.1:0}";
        topic = "\${KAFKA_TOPIC:-tdx-google}";
        encoding = {
          codec = "json";
          compression = "lz4";
        };
      };
    };
  };
  systemd.services.vector = {
    after = [ "network-online.target" "metadata.service" ];
    requires = [ "network-online.target" "metadata.service" ];
    path = [ pkgs.curl pkgs.coreutils ];
    serviceConfig.EnvironmentFile = "-/run/env/env";
  };
}
