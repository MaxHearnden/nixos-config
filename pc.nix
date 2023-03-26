{ config, inputs, lib, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
  ];
  services = {
    xserver = {
      videoDrivers = [ "nvidia" ];
    };
  };
  boot = {
    extraModulePackages = [
      config.boot.kernelPackages.rtl88x2bu
    ];
  };
  networking = {
    hostName = "max-nixos-pc";
  };
}