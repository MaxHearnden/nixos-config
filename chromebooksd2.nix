{ lib, pkgs, ... }:

{
  boot = {
    loader = {
      grub = {
        efiInstallAsRemovable = true;
      };
      efi = {
        canTouchEfiVariables = lib.mkForce false;
      };
    };
  };
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking = {
    firewall = {
      interfaces = {
        net-dhcp = {
          allowedTCPPorts = [ 53 ];
          allowedUDPPorts = [ 53 ];
        };
      };
    };
    hostName = "max-nixos-chromebooksd2";
    hosts =
      lib.listToAttrs (
        lib.genList (index:
          lib.nameValuePair "192.168.2.1${toString (index + 1)}" [ "nixos-slot${toString (index + 1)}"]
        ) 7
      );
    interfaces = {
      net-dhcp = {
        ipv4 = {
          addresses = [
            {
              address = "192.168.2.1";
              prefixLength = 24;
            }
          ];
        };
        useDHCP = false;
      };
    };
    nat = {
      enable = true;
      externalInterface = "wlp2s0";
      internalInterfaces = [
        "net-dhcp"
      ];
    };
    networkmanager = {
      unmanaged = [
        "net-dhcp"
      ];
    };
  };
  services = {
    kea = {
      dhcp4 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = [
              "net-dhcp"
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
    };
  };
  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];
  systemd = {
    network = {
      links = {
        "10-net-dhcp" = {
          linkConfig = {
            Name = "net-dhcp";
            NamePolicy = "";
          };
          matchConfig = {
            MACAddress = "9c:eb:e8:0f:91:63";
          };
        };
      };
    };
  };
}
