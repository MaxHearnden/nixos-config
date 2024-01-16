{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, self }:
  let inherit (nixpkgs) legacyPackages lib; in {
    nixosConfigurations = lib.genAttrs lib.systems.flakeExposed (system:
      lib.nixosSystem {
        inherit system;
        modules = [ ./configuration.nix ];
      });
    packages = lib.genAttrs lib.systems.flakeExposed (system: {
      default = self.nixosConfigurations.${system}.config.system.build.vm;
    });
  };
}
