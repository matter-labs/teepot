{ pkgs
, nixosSystem
, formatModule
, system
, specialArgs ? { }
, modules ? [ ]
}:
let
  image = nixosSystem {
    inherit pkgs specialArgs;
    modules =
      [
        formatModule
        (
          { lib, ... }: {
            options = {
              fileExtension = lib.mkOption {
                type = lib.types.str;
                description = "Declare the path of the wanted file in the output directory";
                default = "";
              };
              formatAttr = lib.mkOption {
                type = lib.types.str;
                description = "Declare the default attribute to build";
              };
            };
          }
        )
      ]
      ++ modules;
  };
in
image.config.system.build.${image.config.formatAttr}
