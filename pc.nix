{ config, inputs, lib, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
  ];
  services = {
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = true;
        };
      };
      videoDrivers = [ "nvidia" ];
    };
  };
  boot = {
    extraModulePackages = [
      config.boot.kernelPackages.rtl88x2bu
    ];
    kernelPackages = lib.mkForce (import inputs.nixpkgs-unstable {
      localSystem = config.nixpkgs.localSystem;
      config = {
        allowUnfree = true;
      };
    }).linuxKernel.packages.linux_6_1;
    loader = {
      grub = {
        useOSProber = true;
        gfxmodeEfi = "1920x1080,auto";
      };
    };
    tmpOnTmpfs = true;
  };
  networking = {
    hostName = "max-nixos-pc";
  };
}