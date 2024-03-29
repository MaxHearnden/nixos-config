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
    firewall = {
      extraInputRules = ''
        iifname "eno1.2" udp dport 67 meta nfproto ipv4 accept comment "kea4 server"
        ip6 daddr { fe80::/64, ff02::1:2, ff02::2 } udp dport 547 iifname "eno1.2" accept comment "kea6 server"
      '';
    };
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
    nat = {
      enable = true;
      externalInterface = "eno1.1";
      internalInterfaces = [
        "eno1.2"
      ];
    };
    networkmanager.enable = false;
    useNetworkd = true;
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
    kea = {
      dhcp4 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = [
              "eno1.2"
            ];
          };
          lease-database = {
            name = "/var/lib/kea/dhcp4.leases";
            persist = true;
            type = "memfile";
          };
          rebind-timer = 2000;
          renew-timer = 1000;
          subnet4 = [
            {
              pools = [
                {
                  pool = "192.168.2.20 - 192.168.2.240";
                }
              ];
              subnet = "192.168.2.0/24";

              option-data = [
                {
                  name = "routers";
                  data = "192.168.2.1";
                }
              ];
              reservations = [
                {
                  hw-address = "48:da:35:60:0e:19";
                  ip-address = "192.168.2.10";
                }
                {
                  hw-address = "48:da:35:60:0e:18";
                  hostname = "nixos-slot1";
                  ip-address = "192.168.2.11";
                }
                {
                  hw-address = "48:da:35:60:0e:12";
                  hostname = "nixos-slot2";
                  ip-address = "192.168.2.12";
                }
                {
                  hw-address = "48:da:35:60:0e:16";
                  hostname = "nixos-slot3";
                  ip-address = "192.168.2.13";
                }
                {
                  hw-address = "48:da:35:60:0e:14";
                  hostname = "nixos-slot4";
                  ip-address = "192.168.2.14";
                }
                {
                  hw-address = "56:44:6a:05:fd:90";
                  hostname = "nixos-slot5";
                  ip-address = "192.168.2.15";
                }
                {
                  hw-address = "48:da:35:60:0e:0e";
                  hostname = "nixos-slot6";
                  ip-address = "192.168.2.16";
                }
                {
                  hw-address = "48:da:35:60:0e:28";
                  hostname = "nixos-slot7";
                  ip-address = "192.168.2.17";
                }
                {
                  hw-address = "36:a9:52:d4:e6:f8";
                  ip-address = "192.168.2.18";
                }
              ];
            }
          ];
        };
      };
      dhcp6 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = [
              "eno1.2"
            ];
          };
          lease-database = {
            name = "/var/lib/kea/dhcp6.leases";
            persist = true;
            type = "memfile";
          };
          rebind-timer = 2000;
          renew-timer = 1000;
          subnet6 = [
            {
              id = 1;
              pools = [
                {
                  pool = "fd80:1234::20 - fd80:1234:ffff:ffff:ffff:ffff:ffff:ffff";
                }
              ];
              subnet = "fd80:1234::/32";
              interface = "eno1.2";

              reservations = [
                {
                  hw-address = "48:da:35:60:0e:19";
                  ip-addresses = ["fd80:1234::10"];
                }
                {
                  hw-address = "48:da:35:60:0e:18";
                  hostname = "nixos-slot1";
                  ip-addresses = ["fd80:1234::11"];
                }
                {
                  hw-address = "48:da:35:60:0e:12";
                  hostname = "nixos-slot2";
                  ip-addresses = ["fd80:1234::12"];
                }
                {
                  hw-address = "48:da:35:60:0e:16";
                  hostname = "nixos-slot3";
                  ip-addresses = ["fd80:1234::13"];
                }
                {
                  hw-address = "48:da:35:60:0e:14";
                  hostname = "nixos-slot4";
                  ip-addresses = ["fd80:1234::14"];
                }
                {
                  hw-address = "56:44:6a:05:fd:90";
                  hostname = "nixos-slot5";
                  ip-addresses = ["fd80:1234::15"];
                }
                {
                  hw-address = "48:da:35:60:0e:0e";
                  hostname = "nixos-slot6";
                  ip-addresses = ["fd80:1234::16"];
                }
                {
                  hw-address = "48:da:35:60:0e:28";
                  hostname = "nixos-slot7";
                  ip-addresses = ["fd80:1234::17"];
                }
                {
                  hw-address = "36:a9:52:d4:e6:f8";
                  ip-addresses = ["fd80:1234::18"];
                }
              ];
            }
          ];
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
      enable = true;
      netdevs = {
        vlan1 = {
          netdevConfig = {
            Kind = "vlan";
            Name = "eno1.1";
          };
          vlanConfig = {
            Id = 1;
          };
        };
        vlan2 = {
          netdevConfig = {
            Kind = "vlan";
            Name = "eno1.2";
          };
          vlanConfig = {
            Id = 2;
          };
        };
      };
      networks = {
        "10-eno1.2" = {
          matchConfig = {
            Name = "eno1.2";
          };
          DHCP = "no";
          networkConfig = {
            IPv6SendRA = true;
          };
          linkConfig = {
            ARP = true;
          };
          ipv6SendRAConfig = {
            Managed = true;
            RouterLifetimeSec = 0;
          };
          ipv6Prefixes = [
            {
              ipv6PrefixConfig = {
                Prefix = "fd80:1234::/32";
              };
            }
          ];
          # networkConfig = {
          #   DHCPServer = true;
          # };
          address = [ "192.168.2.1/24" "fd80:1234::1/32" ];
          # dhcpServerConfig = {
          #   EmitDNS = true;
          #   PoolOffset = 20;
          #   EmitRouter = true;
          # };
        };
        "10-eno1.1" ={
          matchConfig = {
            Name = "eno1.1";
          };
          linkConfig = {
            ARP = true;
          };
          DHCP = "yes";
        };
        "10-eno1" = {
          matchConfig = {
            Name = "eno1";
          };
          DHCP = "no";
          linkConfig = {
            ARP = false;
          };
          vlan = ["eno1.1" "eno1.2"];
        };
      };
      wait-online.enable = false;
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
