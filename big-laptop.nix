{ pkgs, lib, ... }:

{
  boot = {
    extraModprobeConfig = "options iwlwifi 11n_disable=1";
    kernelPackages = lib.mkForce pkgs.linuxPackages;
  };
  hardware = {
    graphics.extraPackages = [ pkgs.intel-media-driver pkgs.nvidia-vaapi-driver ];
    nvidia.open = true;
    tuxedo-drivers = {
      enable = true;
    };
  };
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  networking = {
    firewall.interfaces.enp45s0 = {
      allowedTCPPorts = [ 9943 9944 ];
      allowedUDPPorts = [ 67 9943 9944 ];
    };
    hostName = "max-nixos-laptop";
  };
  services = {
    logind.settings.Login.HandleLidSwitch = "ignore";
    xserver.videoDrivers = [ "nvidia" ];
  };
  time = {
    hardwareClockInLocalTime = true;
  };
}
