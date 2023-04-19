{ config, inputs, lib, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
  ];
  services = {
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
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
    tmpOnTmpfsSize = "100%";
  };
  networking = {
    hostName = "max-nixos-pc";
  };
  nix.buildMachines = [
    {
      systems = [ "x86_64-darwin" ];
      sshUser = "max";
      protocol = "ssh-ng";
      hostName = "172.28.13.156?remote-program=/home/max/ssh-mac-x86";
      maxJobs = 4;
    }
    {
      systems = [ "aarch64-darwin" ];
      sshUser = "max";
      protocol = "ssh-ng";
      hostName = "172.28.13.156?remote-program=/home/max/ssh-mac";
      maxJobs = 8;
    }
  ];
  nix.distributedBuilds = true;
  nix.settings.builders-use-substitutes = true;

}
