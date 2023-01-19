{
  #inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  #inputs.RedNix.url = "github:redcode-labs/rednix";
  #inputs.hackpkgs.follows = "RedNix/hackpkgs";
  inputs.haskell-nix.url = "github:input-output-hk/haskell.nix";
  #inputs.obelisk = {
  #  type = "github";
  #  owner = "obsidiansystems";
  #  repo = "obelisk";
  #  ref = "master";
  #  flake = false;
  #};
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  #inputs.nixpkgs-mipsel.url = "github:maxHearnden/nixpkgs/patch-1";
  outputs = { self, nixpkgs, ... }@inputs: {
    nixosConfigurations.max-nixos-workstation = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./workstation.nix ];
    };
    nixosConfigurations.max-nixos-dell = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./dell.nix ];
    };
    hydraJobs = builtins.mapAttrs (_: config: config.config.system.build.toplevel) self.nixosConfigurations;
  };
}
