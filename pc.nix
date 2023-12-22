{ config, inputs, lib, pkgs, ... }: {
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
            search --set root --fs-uuid A6CD-C355
            chainloader /EFI/ubuntu/shimx64.efi
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
    };
  };
  networking = {
    hostName = "max-nixos-pc";
  };
  services = {
    btrbk = {
      instances = {
        pc = {
          settings = {
            volume = {
              "/nexus" = {
                subvolume = "@NixOS";
                ssh_user = "btrbk";
                send_compressed_data = "yes";
                stream_buffer = "25%";
                stream_compress = "zstd";
                target = "ssh://172.28.10.244/nexus/snapshots/per-device/pc";
                snapshot_dir = "/nexus/snapshots/btrbk";
              };
            };
          };
        };
      };
    };
    ratbagd = {
      enable = true;
    };
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

  users = {
    users = {
      btrbk = {
        packages = with pkgs; [
          zstd
        ];
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
    };
  };

}
