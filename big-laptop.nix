{ pkgs, lib, ... }:

{
  boot = {
    extraModprobeConfig = "options iwlwifi 11n_disable=1";
    kernelPackages = lib.mkForce pkgs.linuxPackages;
  };
  hardware = {
    graphics.extraPackages = [ pkgs.intel-vaapi-driver pkgs.nvidia-vaapi-driver ];
    nvidia.open = true;
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
    xserver.videoDrivers = [ "nvidia" ];
  };
  time = {
    hardwareClockInLocalTime = true;
  };
}
