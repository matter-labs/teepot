{ config
, pkgs
, lib
, ...
}: {
  imports = [
    ./../../../packages/tdx_google/configuration.nix
  ];

  networking.hosts = {
    "127.0.0.100" = [ "metadata.google.internal" ];
    # might want to run kafka on the testing host
    "10.0.2.2" = [ "kafka" ];
  };

  # emulate metadata.google.internal
  services.static-web-server = {
    enable = true;
    listen = "127.0.0.100:80";
    root = ./web-root;
  };

  #  systemd.services.vector = {
  #    environment = {
  #      KAFKA_URLS = "10.0.2.2:9092";
  #      KAFKA_TOPIC = "tdx-google-test";
  #    };
  #  };

  systemd.services.docker_start_container = {
    #    environment = {
    #      CONTAINER_IMAGE = "ghcr.io/matter-labs/tdx-test:pnj1ryxxb8gbzk9wh18s9bcqrzr1z9ff";
    #      CONTAINER_HUB = "docker.io";
    #      CONTAINER_TOKEN = "";
    #      CONTAINER_USER = "";
    #    };

    postStop = ''
      :
    '';
  };

  console.enable = true;

  services.getty.autologinUser = lib.mkOverride 999 "root";

  networking.firewall.allowedTCPPorts = [ 22 ];
  services.sshd.enable = true;
  services.openssh.settings.PermitRootLogin = lib.mkOverride 999 "yes";
  users.users.root.openssh.authorizedKeys.keys = [
    "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDsb/Tr69YN5MQLweWPuJaRGm+h2kOyxfD6sqKEDTIwoAAAABHNzaDo="
    "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBACLgT81iB1iWWVuXq6PdQ5GAAGhaZhSKnveQCvcNnAOZ5WKH80bZShKHyAYzrzbp8IGwLWJcZQ7TqRK+qZdfagAAAAEc3NoOg=="
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAYbUTKpy4QR3s944/hjJ1UK05asFEs/SmWeUbtS0cdA660sT4xHnRfals73FicOoz+uIucJCwn/SCM804j+wtM="
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMNsmP15vH8BVKo7bdvIiiEjiQboPGcRPqJK0+bH4jKD"
  ];

  environment.systemPackages = with pkgs; [
    strace
    tcpdump
    static-web-server
  ];


  fileSystems = {
    "/" = {
      fsType = "ext4";
      device = "/dev/disk/by-id/test";
      options = [ "mode=0755" ];
    };
  };

  boot = {
    loader.grub.enable = false;
    initrd.systemd.enable = true;
  };

  virtualisation.vmVariant = {
    # following configuration is added only when building VM with build-vm
    virtualisation = {
      memorySize = 2048; # Use 2048MiB memory.
      cores = 4;
    };
  };
}
