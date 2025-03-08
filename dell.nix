{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix ./laptop.nix ./guix.nix];
  boot = {
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
    };
  };
  networking = {
    hostName = "max-nixos-dell";
  };
  services = {
    tcsd = {
      enable = true;
    };
  };
}
