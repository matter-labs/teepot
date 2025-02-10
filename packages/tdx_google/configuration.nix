{ lib
, modulesPath
, pkgs
, ...
}: {
  imports = [
    "${toString modulesPath}/profiles/minimal.nix"
    "${toString modulesPath}/profiles/qemu-guest.nix"
  ];

  # the container might want to listen on ports
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [{ from = 1024; to = 65535; }];
  networking.firewall.allowedUDPPortRanges = [{ from = 1024; to = 65535; }];

  services.resolved.enable = true;
  services.resolved.llmnr = "false";
  services.resolved.extraConfig = ''
    [Resolve]
    MulticastDNS=no
  '';

  networking.useNetworkd = lib.mkDefault true;

  # don't fill up the logs
  networking.firewall.logRefusedConnections = false;

  virtualisation.docker.enable = true;

  systemd.services.docker_start_container = {
    description = "The main application container";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "docker.service" ];
    requires = [ "network-online.target" "docker.service" ];
    serviceConfig = {
      Type = "exec";
      User = "root";
    };
    path = [ pkgs.curl pkgs.docker pkgs.teepot.teepot.tdx_extend pkgs.coreutils ];
    script = ''
      set -eu -o pipefail
      : "''${CONTAINER_IMAGE:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_image" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_HUB:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_hub" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_USER:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_user" -H "Metadata-Flavor: Google")}"
      : "''${CONTAINER_TOKEN:=$(curl --silent --fail "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_token" -H "Metadata-Flavor: Google")}"

      : "''${CONTAINER_IMAGE:?Error: Missing CONTAINER_IMAGE}"
      : "''${CONTAINER_HUB:?Error: Missing CONTAINER_HUB}"

      if [[ $CONTAINER_USER ]] && [[ $CONTAINER_TOKEN ]]; then
        docker login -u "$CONTAINER_USER" -p "$CONTAINER_TOKEN" "$CONTAINER_HUB"
      fi

      docker pull "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}"
      DIGEST=$(docker inspect --format '{{.Id}}' "''${CONTAINER_HUB}/''${CONTAINER_IMAGE}")
      DIGEST=''${DIGEST#sha256:}
      echo "Measuring $DIGEST" >&2
      test -c /dev/tdx_guest && tdx-extend --digest "$DIGEST" --rtmr 3
      exec docker run --init --privileged "sha256:$DIGEST"
    '';

    postStop = lib.mkDefault ''
      shutdown --reboot +5
    '';
  };

  services.prometheus.exporters.node = {
    enable = true;
    port = 9100;
    enabledCollectors = [
      "logind"
      "systemd"
    ];
    disabledCollectors = [
      "textfile"
    ];
  };

  environment.systemPackages = with pkgs; [
    teepot.teepot
  ];

  # /var is on tmpfs anyway
  services.journald.storage = "volatile";

  # we can't rely on/trust the hypervisor
  services.timesyncd.enable = false;
  services.chrony = {
    enable = true;
    enableNTS = true;
    servers = [
      "time.cloudflare.com"
      "ntppool1.time.nl"
      "ntppool2.time.nl"
    ];
  };
  systemd.services."chronyd".after = [ "network-online.target" ];

  boot.kernelPackages = lib.mkForce pkgs.linuxPackages_6_12;
  boot.kernelPatches = [
    {
      name = "tdx-rtmr";
      patch = pkgs.fetchurl {
        url = "https://github.com/haraldh/linux/commit/12d08008a5c94175e7a7dfcee40dff33431d9033.patch";
        hash = "sha256-sVDhvC3qnXpL5FRxWiQotH7Nl/oqRBQGjJGyhsKeBTA=";
      };
    }
  ];

  boot.kernelParams = [
    "console=ttyS0,115200n8"
    "random.trust_cpu=on"
  ];

  boot.consoleLogLevel = 7;

  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = [
    "tdx_guest"
    "nvme"
    "sd_mod"
    "dm_mod"
    "ata_piix"
  ];

  boot.initrd.systemd.enable = lib.mkDefault true;

  services.logind.extraConfig = ''
    NAutoVTs=0
    ReserveVT=0
  '';

  services.dbus.implementation = "broker";

  boot.initrd.systemd.tpm2.enable = lib.mkForce false;
  systemd.tpm2.enable = lib.mkForce false;

  nix.enable = false; # it's a read-only nix store anyway

  security.pam.services.su.forwardXAuth = lib.mkForce false;

  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;

  system.stateVersion = lib.version;
  system.switch.enable = lib.mkForce false;

  documentation.info.enable = lib.mkForce false;
  documentation.nixos.enable = lib.mkForce false;
  documentation.man.enable = lib.mkForce false;
  documentation.enable = lib.mkForce false;

  services.udisks2.enable = false; # udisks has become too bloated to have in a headless system

  # Get rid of the perl ecosystem to minimize the TCB and disk size

  # Remove perl from activation
  system.etc.overlay.enable = lib.mkDefault true;
  services.userborn.enable = lib.mkDefault true;

  # Random perl remnants
  system.disableInstallerTools = lib.mkForce true;
  programs.less.lessopen = lib.mkDefault null;
  programs.command-not-found.enable = lib.mkDefault false;
  boot.enableContainers = lib.mkForce false;
  boot.loader.grub.enable = lib.mkDefault false;
  environment.defaultPackages = lib.mkDefault [ ];

  # Check that the system does not contain a Nix store path that contains the
  # string "perl".
  system.forbiddenDependenciesRegexes = [ "perl" ];
}
