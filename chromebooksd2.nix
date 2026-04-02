{ lib, pkgs, ... }:

{
  boot = {
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
  services.ip-mesh = {
    self = lib.mkForce "chromebook";
  };
  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];
}
