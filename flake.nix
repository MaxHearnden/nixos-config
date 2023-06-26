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
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.math104.url = "git+http://172.28.10.244:3000/zandoodle/Math104";
  inputs.math104.inputs.nixpkgs.follows = "nixpkgs";
  inputs.latest-system.url = "git+http://172.28.10.244:3000/zandoodle/latest-system";
  inputs.latest-system.inputs.nixpkgs.follows = "nixpkgs";
  inputs.vscode-extensions.url = "github:nix-community/nix-vscode-extensions";
  inputs.vscode-extensions.inputs.nixpkgs.follows = "nixpkgs-unstable";
  #inputs.nixpkgs-mipsel.url = "github:maxHearnden/nixpkgs/patch-1";
  outputs = { self, nixpkgs, ... }@inputs: {
    packages.x86_64-linux.default =
      nixpkgs.legacyPackages.x86_64-linux.linkFarm "systems"
        (builtins.attrValues
          (builtins.mapAttrs (name: path: {inherit name path;}) self.hydraJobs)
        );
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
    nixosConfigurations.max-nixos-chromebooksd2 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./chromebooksd2.nix ];
    };
    nixosConfigurations.max-nixos-laptop = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./big-laptop.nix ];
    };
    nixosConfigurations.max-nixos-pc = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./pc.nix ];
    };
    hydraJobs = builtins.mapAttrs (_: config: config.config.system.build.toplevel) self.nixosConfigurations;
  };
}
