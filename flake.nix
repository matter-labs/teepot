{
  description = "teepot";

  nixConfig.extra-substituters = [
    "https://nixsgx.cachix.org"
  ];
  nixConfig.extra-trusted-public-keys = [
    "nixsgx.cachix.org-1:tGi36DlY2joNsIXOlGnSgWW0+E094V6hW0umQRo/KoE="
  ];

  inputs = {
    nixsgx-flake.url = "github:matter-labs/nixsgx";
    nixpkgs.follows = "nixsgx-flake/nixpkgs";
    snowfall-lib.follows = "nixsgx-flake/snowfall-lib";

    vault-auth-tee-flake = {
      url = "github:matter-labs/vault-auth-tee";
      inputs.nixpkgs.follows = "nixsgx-flake/nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixsgx-flake/nixpkgs";
    };

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixsgx-flake/nixpkgs";
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
