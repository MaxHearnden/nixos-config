{ pkgs, ... }:

{
  boot = {
    extraModprobeConfig = "options iwlwifi 11n_disable=1";
    loader = {
      grub = {
        useOSProber = true;
      };
    };
  };
  hardware = {
    nvidia = {
      prime = {
        intelBusId = "PCI:0:2:0";
        nvidiaBusId = "PCI:1:0:0";
        offload = {
          enable = true;
        };
      };
    };
    # tuxedo-keyboard = {
    #   enable = true;
    # };
  };
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  networking = {
    hostName = "max-nixos-laptop";
  };
  services = {
    logind = {
      lidSwitch = "ignore";
    };
    xserver = {
      videoDrivers = [
        "nvidia"
      ];
    };
  };
  time = {
    hardwareClockInLocalTime = true;
  };
}
