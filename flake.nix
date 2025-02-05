{
  inputs.latest-system.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/latest-system";
  inputs.latest-system.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.vscode-extensions.url = "github:nix-community/nix-vscode-extensions";
  inputs.vscode-extensions.inputs.nixpkgs.follows = "nixpkgs-unstable";
  inputs.nixos-kexec.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-kexec";
  inputs.nixos-kexec.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nix-minecraft.url = "git+https://github.com/Infinidoge/nix-minecraft";
  inputs.nix-minecraft.inputs.nixpkgs.follows = "nixpkgs";
  outputs = { self, nixpkgs, ... }@inputs: {
    packages.x86_64-linux.default =
      nixpkgs.legacyPackages.x86_64-linux.linkFarm "systems"
        (builtins.attrValues
          (builtins.mapAttrs (name: path: {inherit name path;}) self.hydraJobs)
        );
    packages.x86_64-linux.systems-with-closure =
      nixpkgs.legacyPackages.x86_64-linux.runCommandNoCC "systems-with-closure" {} ''
        mkdir $out
        ln -s ${self.packages.x86_64-linux.default} $out/systems
        ln -s ${nixpkgs.legacyPackages.x86_64-linux.closureInfo {rootPaths = map (drv: drv.drvPath) (builtins.attrValues self.hydraJobs);}} $out/closure
      '';
    packages.x86_64-linux.vms =
      nixpkgs.legacyPackages.x86_64-linux.symlinkJoin
        {
          name = "vms";
          paths =
            (builtins.attrValues
              (builtins.mapAttrs (name: system: system.config.system.build.vm) self.nixosConfigurations));
        };
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
