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

    crane = {
      url = "github:ipetkov/crane?tag=v0.17.3";
      inputs.nixpkgs.follows = "nixsgx-flake/nixpkgs";
    };
  };

  outputs = inputs:
    let src = ./.; in
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      inherit src;

      snowfall.namespace = "teepot";

      channels-config = {
        allowUnfree = true;
      };

      overlays = with inputs; [
        nixsgx-flake.overlays.default
        vault-auth-tee-flake.overlays.default
        rust-overlay.overlays.default
        # somehow the original `src` is not available anymore
        (final: prev: { teepotCrate = prev.pkgs.callPackage ./teepot-crate.nix { inherit inputs; inherit src; }; })
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
