{ config, inputs, lib, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
  ];
  boot = {
    # extraModulePackages = [
    #   config.boot.kernelPackages.rtl88x2bu
    # ];
    # kernelPackages = lib.mkForce (import inputs.nixpkgs-unstable {
    #   localSystem = config.nixpkgs.localSystem;
    #   config = {
    #     allowUnfree = true;
    #   };
    # }).linuxKernel.packages.linux_6_1;
    loader = {
      grub = {
        extraEntries = ''
          menuentry "Ubuntu" {
            chainloader @bootRoot@/EFI/ubuntu/shimx64.efi
          }
        '';
        gfxmodeEfi = "1920x1080,auto";
        useOSProber = true;
      };
    };
    tmp = {
      tmpfsSize = "100%";
      useTmpfs = true;
    };
  };
  fileSystems = {
    "/nexus" = {
      device = "/dev/disk/by-uuid/23d34216-8396-41b9-ae01-290d9fbf1a6d";
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "nosuid" "nodev" "noatime" ];
    }
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
      # xrandrHeads = [
      #   "HDMI-0"
      #   {
      #     output = "DVI-D-0";
      #     primary = true;
      #   }
      # ];
    };
  };

}
