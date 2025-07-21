{
  description = "teepot";

  nixConfig = {
    extra-substituters = [ "https://static.188.92.12.49.clients.your-server.de/tee-pot" ];
    extra-trusted-public-keys = [ "tee-pot:SS6HcrpG87S1M6HZGPsfo7d1xJccCGev7/tXc5+I4jg=" ];
  };

  inputs = {
    nixpkgs-25-05.url = "github:nixos/nixpkgs/nixos-25.05";
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

    crane.url = "github:ipetkov/crane?ref=efd36682371678e2b6da3f108fdb5c613b3ec598"; #  v0.20.3
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
        (next: prev: {
          # need recent cargo-deny understanding the 2024 edition
          inherit (inputs.nixpkgs-25-05.legacyPackages.${prev.system})
            cargo-deny;
        })
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
