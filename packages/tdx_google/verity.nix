{ config
, pkgs
, lib
, modulesPath
, ...
}:
let
  inherit (config.image.repart.verityStore) partitionIds;
in
{
  imports = [
    "${toString modulesPath}/image/repart.nix"
  ];

  fileSystems = {
    "/" = {
      fsType = "tmpfs";
      options = [ "mode=0755" "noexec" ];
    };

    "/dev/shm" = {
      fsType = "tmpfs";
      options = [ "defaults" "nosuid" "noexec" "nodev" "size=2G" ];
    };

    "/run" = {
      fsType = "tmpfs";
      options = [ "defaults" "mode=0755" "nosuid" "noexec" "nodev" "size=512M" ];
    };

    "/usr" = {
      device = "/dev/mapper/usr";
      # explicitly mount it read-only otherwise systemd-remount-fs will fail
      options = [ "ro" ];
      fsType = config.image.repart.partitions.${partitionIds.store}.repartConfig.Format;
    };

    # bind-mount the store
    "/nix/store" = {
      device = "/usr/nix/store";
      options = [ "bind" ];
    };
  };

  image.repart = {
    verityStore = {
      enable = true;
      ukiPath = "/EFI/BOOT/BOOTx64.EFI";
    };

    partitions = {
      ${partitionIds.esp} = {
        # the UKI is injected into this partition by the verityStore module
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "64M";
        };
      };
      ${partitionIds.store-verity}.repartConfig = {
        Minimize = "best";
      };
      ${partitionIds.store}.repartConfig = {
        Minimize = "best";
        Format = "squashfs";
      };
    };
  };

  boot = {
    loader.grub.enable = false;
    initrd.systemd.enable = true;
  };

  system.image = {
    id = lib.mkDefault "nixos-appliance";
    version = "1";
  };

  # don't create /usr/bin/env
  # this would require some extra work on read-only /usr
  # and it is not a strict necessity
  system.activationScripts.usrbinenv = lib.mkForce "";

  boot.kernelParams = [
    "systemd.verity_usr_options=panic-on-corruption"
    "panic=30"
    "boot.panic_on_fail" # reboot the machine upon fatal boot issues
    "lockdown=1"
  ];

  system.build.vmdk_verity =
    config.system.build.finalImage.overrideAttrs
      (
        finalAttrs: previousAttrs:
          let
            kernel = config.boot.uki.settings.UKI.Linux;
            ukifile = "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
          in
          {
            nativeBuildInputs =
              previousAttrs.nativeBuildInputs
              ++ [
                pkgs.qemu
                pkgs.teepot.teepot.rtmr_calc
              ];

            postInstall = ''
              qemu-img convert -f raw -O vmdk \
                $out/${config.image.repart.imageFileBasename}.raw \
                $out/${config.image.repart.imageFileBasename}.vmdk
              qemu-img info \
                $out/${config.image.repart.imageFileBasename}.vmdk
              echo "kernel: ${kernel}"
              echo "uki: ${ukifile}"
              rtmr-calc \
               --image $out/${config.image.repart.imageFileBasename}.raw \
               --bootefi "${ukifile}" \
               --kernel "${kernel}" | tee $out/${config.image.repart.imageFileBasename}_rtmr.json
              rm -vf $out/${config.image.repart.imageFileBasename}.raw
            '';
          }
      );

  formatAttr = lib.mkForce "vmdk_verity";
  fileExtension = lib.mkForce ".raw";
}
