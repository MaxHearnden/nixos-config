{ pkgs, lib, ... }:

{
  boot = {
    extraModprobeConfig = "options iwlwifi 11n_disable=1";
    kernelPackages = lib.mkForce pkgs.linuxPackages;
  };
  hardware = {
    tuxedo-drivers = {
      enable = true;
    };
  };
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  networking = {
    hostName = "max-nixos-laptop";
  };
  services = {
    logind = {
      lidSwitch = "ignore";
    };
  };
  time = {
    hardwareClockInLocalTime = true;
  };
}
