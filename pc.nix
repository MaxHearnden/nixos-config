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
    "/nix" = {
      device = "/dev/disk/by-uuid/23d34216-8396-41b9-ae01-290d9fbf1a6d";
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "nosuid" "nodev" "noatime" "subvol=/nix" ];
    };
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
      extraPackages = with pkgs; [
        zstd
      ];
      instances = {
        pc = {
          settings = {
            target_preserve_min = "no";
            target_preserve = "2w 6m";
            ssh_user = "btrbk";
            send_compressed_data = "yes";
            stream_buffer = "25%";
            stream_compress = "zstd";
            snapshot_preserve = "14d 2w 3m";
            snapshot_preserve_min = "2d";
            snapshot_dir = "snapshots/btrbk";
            transaction_syslog = "user";
            volume = {
              "/nexus" = {
                target = "ssh://172.28.10.244/Big/backups/pc";
                subvolume = "@NixOS";
              };
              "ssh://172.28.10.244/nexus" = {
                subvolume = {
                  "@NixOS" = {
                    snapshot_name = "@NixOS-for-pc";
                  };
                };
                target = "/nexus/backups/workstation";
                snapshot_preserve = "1d";
                snapshot_preserve_min = "no";
                incremental = "strict";
              };
              "ssh://172.28.10.244/Big" = {
                subvolume = {
                  "shared" = {
                    snapshot_name = "shared-for-pc";
                  };
                };
                target = "/nexus/backups/workstation";
                snapshot_preserve = "1d";
                snapshot_preserve_min = "no";
                incremental = "strict";
              };
            };
          };
        };
      };
      # sshAccess = [
      #   {
      #     key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMqC2ozMYl/Nh9vGcrsxuay0jSl+uOek3K4NMSQkgah btrbk@max-nixos-workstation";
      #     roles = [
      #       "receive"
      #       "delete" 
      #     ];
      #   }
      # ];
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

  systemd = {
    services = {
      btrbk-pc = {
        restartIfChanged = false;
      };
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
