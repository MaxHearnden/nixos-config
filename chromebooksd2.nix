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
