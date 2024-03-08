{
  description = "teepot";

  nixConfig.extra-substituters = [
    "https://nixsgx.cachix.org"
  ];
  nixConfig.extra-trusted-public-keys = [
    "nixsgx.cachix.org-1:tGi36DlY2joNsIXOlGnSgWW0+E094V6hW0umQRo/KoE="
  ];

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    nixsgx-flake = {
      url = "github:matter-labs/nixsgx";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    vault-auth-tee-flake = {
      url = "github:matter-labs/vault-auth-tee";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    snowfall-lib = {
      url = "github:snowfallorg/lib?rev=92803a029b5314d4436a8d9311d8707b71d9f0b6";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay?rev=3ad32bb27c700b59306224e285b66577e3532dfc";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      src = ./.;

      package-namespace = "teepot";

      overlays = with inputs; [
        nixsgx-flake.overlays.default
        vault-auth-tee-flake.overlays.default
        rust-overlay.overlays.default
      ];

      alias = {
        packages = {
          default = "teepot";
        };
        shells = {
          default = "teepot";
        };
      };

      outputs-builder = channels: {
        formatter = channels.nixpkgs.nixpkgs-fmt;

        checks = {
          inherit
            (channels.nixpkgs.teepot) cargoFmt;
          inherit
            (channels.nixpkgs.teepot) cargoClippy;
          inherit
            (channels.nixpkgs.teepot) cargoDeny;
        };

      };
    };
}
