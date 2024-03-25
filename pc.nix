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
        # useOSProber = true;
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
    # firewall = {
    #   interfaces = {
    #     net-dhcp = {
    #       allowedTCPPorts = [ 5000 53 ];
    #       allowedUDPPorts = [ 53 ];
    #     };
    #   };
    # };
    hostName = "max-nixos-pc";
    # hosts =
    #   lib.listToAttrs (
    #     lib.genList (index:
    #       lib.nameValuePair "192.168.2.1${toString (index + 1)}" [ "nixos-slot${toString (index + 1)}"]
    #     ) 7
    #   );
    # interfaces = {
    #   net-dhcp = {
    #     ipv4 = {
    #       addresses = [
    #         {
    #           address = "192.168.2.1";
    #           prefixLength = 24;
    #         }
    #       ];
    #     };
    #     useDHCP = false;
    #   };
    # };
    # nat = {
    #   enable = true;
    #   externalInterface = "eno1";
    #   internalInterfaces = [
    #     "net-dhcp"
    #   ];
    # };
    # networkmanager = {
    #   unmanaged = [
    #     "net-dhcp"
    #   ];
    # };
  };
  services = {
    btrbk = {
      extraPackages = with pkgs; [
        zstd
      ];
      instances = {
        pc = {
          settings = {
            volume = {
              "ssh://max-nixos-workstation-zerotier/nexus" = {
                subvolume = {
                  "@NixOS" = {
                    snapshot_name = "@NixOS-for-pc";
                  };
                };
                target = "/nexus/backups/workstation";
                snapshot_preserve = "1w";
                snapshot_preserve_min = "latest";
                incremental = "strict";
              };
              "ssh://max-nixos-workstation-zerotier/Big" = {
                subvolume = {
                  "shared" = {
                    snapshot_name = "shared-for-pc";
                  };
                };
                target = "/nexus/backups/workstation";
                snapshot_preserve = "1w";
                snapshot_preserve_min = "latest";
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
    # kea = {
    #   dhcp4 = {
    #     enable = true;
    #     settings = {
    #       interfaces-config = {
    #         interfaces = [
    #           "net-dhcp"
    #         ];
    #       };
    #       lease-database = {
    #         name = "/var/lib/kea/dhcp4.leases";
    #         persist = true;
    #         type = "memfile";
    #       };
    #       rebind-timer = 2000;
    #       renew-timer = 1000;
    #       subnet4 = [
    #         {
    #           pools = [
    #             {
    #               pool = "192.168.2.20 - 192.168.2.240";
    #             }
    #           ];
    #           subnet = "192.168.2.0/24";

    #           option-data = [
    #             {
    #               name = "routers";
    #               data = "192.168.2.1";
    #             }
    #           ];
    #           reservations = [
    #             {
    #               hw-address = "48:da:35:60:0e:19";
    #               ip-address = "192.168.2.10";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:18";
    #               hostname = "nixos-slot1";
    #               ip-address = "192.168.2.11";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:12";
    #               hostname = "nixos-slot2";
    #               ip-address = "192.168.2.12";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:16";
    #               hostname = "nixos-slot3";
    #               ip-address = "192.168.2.13";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:14";
    #               hostname = "nixos-slot4";
    #               ip-address = "192.168.2.14";
    #             }
    #             {
    #               hw-address = "56:44:6a:05:fd:90";
    #               hostname = "nixos-slot5";
    #               ip-address = "192.168.2.15";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:0e";
    #               hostname = "nixos-slot6";
    #               ip-address = "192.168.2.16";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:28";
    #               hostname = "nixos-slot7";
    #               ip-address = "192.168.2.17";
    #             }
    #             {
    #               hw-address = "36:a9:52:d4:e6:f8";
    #               ip-address = "192.168.2.18";
    #             }
    #           ];
    #         }
    #       ];
    #     };
    #   };
    # };
    ratbagd = {
      enable = true;
    };
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
      };
      # xrandrHeads = [
      #   "HDMI-0"
      #   {
      #     output = "DVI-D-0";
      #     primary = true;
      #   }
      # ];
    };
  };
  # systemd = {
  #   network = {
  #     links = {
  #       "10-net-dhcp" = {
  #         linkConfig = {
  #           Name = "net-dhcp";
  #           NamePolicy = "";
  #         };
  #         matchConfig = {
  #           MACAddress = "9c:eb:e8:0f:91:63";
  #         };
  #       };
  #     };
  #   };
  # };
  systemd = {
    network = {
      netdevs = {
        vlan2 = {
          netdevConfig = {
            Kind = "vlan";
            Name = "eno1.2";
          };
          vlanConfig = {
            id = 2;
          };
        };
      };
      networks = {
        "10-eno1" = {
          matchConfig = {
            Name = "eno1";
          };
          networkConfig = {
            vlan = "vlan2";
          };
        };
      };
    };
    services = {
      btrbk-pc = {
        serviceConfig = {
          RestrictSUIDSGID = lib.mkForce false;
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
    };
  };

  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];

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
