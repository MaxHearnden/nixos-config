{
  # inputs.keyboard_mouse_emulate_on_raspberry.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/keyboard_mouse_emulate_on_raspberry";
  # inputs.keyboard_mouse_emulate_on_raspberry.inputs.nixpkgs.follows = "nixpkgs";
  inputs.latest-system.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/latest-system";
  inputs.latest-system.inputs.nixpkgs.follows = "nixpkgs";
  # inputs.math104.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/Math104";
  # inputs.math104.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.vscode-extensions.url = "github:nix-community/nix-vscode-extensions";
  inputs.vscode-extensions.inputs.nixpkgs.follows = "nixpkgs-unstable";
  # inputs.tobig.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/tobig";
  # inputs.tobig.inputs.nixpkgs.follows = "nixpkgs";
  # inputs.rename-exchange.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/rename-exchange";
  # inputs.rename-exchange.inputs.nixpkgs.follows = "nixpkgs";
  # inputs.shh.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/shh-nix";
  # inputs.shh.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixos-kexec.url = "git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-kexec";
  inputs.nixos-kexec.inputs.nixpkgs.follows = "nixpkgs";
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
    # nixosConfigurations.max-nixos-laptop = nixpkgs.lib.nixosSystem {
    #   system = "x86_64-linux";
    #   specialArgs = {inherit inputs;};
    #   modules = [ ./big-laptop.nix ];
    # };
    nixosConfigurations.max-nixos-pc = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs;};
      modules = [ ./pc.nix ];
    };
    hydraJobs = builtins.mapAttrs (_: config: config.config.system.build.toplevel) self.nixosConfigurations;
  };
}
