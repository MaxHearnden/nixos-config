{
  inputs = {
    latest-system = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/latest-system";
    };
    nix-minecraft = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:Infinidoge/nix-minecraft";
    };
    nixos-kexec = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-kexec";
    };
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    plover-flake = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:opensteno/plover-flake";
    };
    vscode-extensions = {
      inputs.nixpkgs.follows = "nixpkgs-unstable";
      url = "github:nix-community/nix-vscode-extensions";
    };
  };
  outputs = { self, nixpkgs, ... }@inputs: {
    hydraJobs = builtins.mapAttrs (_: config: config.config.system.build.toplevel) self.nixosConfigurations;
    nixosConfigurations = {
      max-nixos-chromebooksd2 = nixpkgs.lib.nixosSystem {
        modules = [ ./chromebooksd2.nix ];
        specialArgs = {inherit inputs;};
        system = "x86_64-linux";
      };
      max-nixos-dell = nixpkgs.lib.nixosSystem {
        modules = [ ./dell.nix ];
        specialArgs = {inherit inputs;};
        system = "x86_64-linux";
      };
      max-nixos-laptop = nixpkgs.lib.nixosSystem {
        modules = [ ./big-laptop.nix ];
        specialArgs = {inherit inputs;};
        system = "x86_64-linux";
      };
      max-nixos-pc = nixpkgs.lib.nixosSystem {
        modules = [ ./pc.nix ];
        specialArgs = {inherit inputs;};
        system = "x86_64-linux";
      };
      max-nixos-workstation = nixpkgs.lib.nixosSystem {
        modules = [ ./workstation.nix ];
        specialArgs = {inherit inputs;};
        system = "x86_64-linux";
      };
    };
    packages.x86_64-linux = {
      default = nixpkgs.legacyPackages.x86_64-linux.linkFarm "systems" (builtins.attrValues (builtins.mapAttrs (name: path: {inherit name path;}) self.hydraJobs));
      zone = nixpkgs.legacyPackages.x86_64-linux.runCommand "zonefile" {} ''
        for system in ${self.packages.x86_64-linux.default}/*; do
          echo "$(basename "$system").systems TXT \"$(readlink "$system")\"" >> $out
        done
      '';
      systems-with-zone =
        nixpkgs.legacyPackages.x86_64-linux.runCommand "systems-with-zone" {} ''
          mkdir $out
          ln -s ${self.packages.x86_64-linux.default} $out/systems
          ln -s ${self.packages.x86_64-linux.zone} $out/zonefile
        '';
      systems-with-closure =
        nixpkgs.legacyPackages.x86_64-linux.runCommand "systems-with-closure" {} ''
          mkdir $out
          ln -s ${self.packages.x86_64-linux.default} $out/systems
          ln -s ${self.packages.x86_64-linux.zone} $out/zonefile
          ln -s ${nixpkgs.legacyPackages.x86_64-linux.closureInfo {rootPaths = map (drv: drv.drvPath) (builtins.attrValues self.hydraJobs);}} $out/closure
        '';
      vms = nixpkgs.legacyPackages.x86_64-linux.symlinkJoin {
        name = "vms";
        paths = (builtins.attrValues (builtins.mapAttrs (name: system: system.config.system.build.vm) self.nixosConfigurations));
      };
    };
  };
}
