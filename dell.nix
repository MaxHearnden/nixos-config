{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix ./laptop.nix];
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
  services.tcsd.enable = true;
  users.users.max.packages = with pkgs; [
    tpm-tools
    tpmmanager
  ];
}
