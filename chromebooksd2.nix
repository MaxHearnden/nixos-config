{ config, pkgs, lib, ... }: {
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking.hostName = "max-nixos-chromebooksd2";
  swapDevices = [ {device = "/swapfile"; size = 4096;} ];
  boot.loader.grub.efiInstallAsRemovable = true;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
}
