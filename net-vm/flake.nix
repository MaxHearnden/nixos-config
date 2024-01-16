{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }:
  let inherit (nixpkgs) legacyPackages lib; in {
    packages = lib.mapAttrs (system: pkgs: {
      default = pkgs.callPackage ./package.nix { };
    }) legacyPackages;
  };
}
