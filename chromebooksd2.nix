{ lib, ... }:

{
  boot = {
    loader = {
      grub = {
        efiInstallAsRemovable = true;
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
  nix = {
    gc = {
      automatic = lib.mkForce false;
    };
  };
  swapDevices = [
    {
      device = "/swapfile";
    }
  ];
}
