{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }: {
    packages = nixpkgs.lib.mapAttrs (system: pkgs: {
      default = pkgs.runCommand "nix-test" {} ''
        "${pkgs.libvirt}/bin/virt-host-validate"
      '';
    }) nixpkgs.legacyPackages;
  };
}
  
