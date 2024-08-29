{ config, lib, pkgs, ... }:

{
  boot = {
    # kernelPatches = [
    #   {
    #     name = "kernel-null-test";
    #     patch = ./null-kernel-warn.patch;
    #   }
    # ];
    extraModulePackages = [(import ./extern-nfs.nix {kernel = config.boot.kernelPackages.kernel;})];
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
      efi = {
        canTouchEfiVariables = lib.mkForce false;
      };
    };
  };
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking = {
    hostName = "max-nixos-chromebooksd2";
  };
  services = {
    tcsd = {
      enable = true;
    };
  };
  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];
}
