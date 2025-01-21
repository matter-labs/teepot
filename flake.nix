{
  description = "teepot";

  nixConfig = {
    extra-substituters = [ "https://attic.teepot.org/tee-pot" ];
    extra-trusted-public-keys = [ "tee-pot:SS6HcrpG87S1M6HZGPsfo7d1xJccCGev7/tXc5+I4jg=" ];
  };

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

    crane.url = "github:ipetkov/crane?ref=8ff9c457d60951bdd37a05ae903423de7ff55c6e"; #  v0.19.3
  };

  outputs = inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      src = ./.;

      snowfall.namespace = "teepot";

      channels-config = {
        allowUnfree = true;
      };

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
        devShells = {
          default = "teepot";
        };
      };

      outputs-builder = channels: {
        formatter = channels.nixpkgs.nixfmt-rfc-style;
      };
    };
}
