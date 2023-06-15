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
  fileSystems = {
    "/mnt/ubuntu" = {
      device = "/dev/nvme1n1p1";
      fsType = "ext4";
      options = [
        "nofail"
        "ro"
      ];
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
    tuxedo-keyboard = {
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
