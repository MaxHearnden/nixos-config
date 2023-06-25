{ config, inputs, lib, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
  ];
  boot = {
    extraModulePackages = [
      config.boot.kernelPackages.rtl88x2bu
    ];
    # kernelPackages = lib.mkForce (import inputs.nixpkgs-unstable {
    #   localSystem = config.nixpkgs.localSystem;
    #   config = {
    #     allowUnfree = true;
    #   };
    # }).linuxKernel.packages.linux_6_1;
    loader = {
      grub = {
        gfxmodeEfi = "1920x1080,auto";
        useOSProber = true;
      };
    };
    tmp = {
      tmpfsSize = "100%";
      useTmpfs = true;
    };
  };
  networking = {
    hostName = "max-nixos-pc";
  };
  services = {
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
      };
      videoDrivers = [ "nvidia" ];
      xrandrHeads = [
        "HDMI-0"
        {
          output = "DVI-D-0";
          primary = true;
        }
      ];
    };
  };

}
