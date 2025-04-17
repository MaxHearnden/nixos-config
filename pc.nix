{ config, inputs, lib, pkgs, ... }: {
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
    ./zone.nix
  ];
  boot = {
    kernelPackages = lib.mkForce pkgs.linuxPackages;
    kernelParams = [
      "console=ttyS0,115200"
      "console=tty0"
    ];
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
    };
    tmp = {
      tmpfsSize = "100%";
      useTmpfs = true;
    };
  };
  environment = {
    etc =
      lib.listToAttrs (map (file: {
        name = "pcrlock.d/${file}";
        value = {
          source = "${inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.systemd.out}/lib/pcrlock.d/${file}";
        };
      }) [ "400-secureboot-separator.pcrlock.d" "500-separator.pcrlock.d" "700-action-efi-exit-boot-services.pcrlock.d" ]) // 
      lib.listToAttrs (map (file: {
        name = "pcrlock.d/${file}";
        value = {
          source = "/run/booted-system/${file}";
        };
      }) [ "650-systemd-boot.pcrlock" "670-kernel.pcrlock" "705-kernel-cmdline.pcrlock" "710-kernel-cmdline.pcrlock" "720-kernel-initrd.pcrlock" ]);
  };
  hardware.nvidia.open = true;
  networking = {
    firewall = {
      extraForwardRules = ''
        udp dport 53 reject
        tcp dport {53, 80} reject
      '';
      filterForward = true;
      interfaces = {
        usb = {
          allowedTCPPorts = [ 53 ];
          allowedUDPPorts = [ 53 67 ];
        };
        ztmjfp7kiq = {
          allowedTCPPorts = [ 8080 9090 11434 ];
        };
      };
    };
    hostName = "max-nixos-pc";
    nat = {
      enable = true;
      externalInterface = "eno1";
      internalInterfaces = [
        "usb"
      ];
    };
    networkmanager.enable = false;
    useNetworkd = true;
  };
  security = {
    tpm2 = {
      enable = true;
      tctiEnvironment = {
        enable = true;
      };
    };
  };
  services = {
    _3proxy = {
      enable = true;
      services = [
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 8080;
          bindAddress = "172.28.13.156";
          extraArguments = "8080 192.168.1.79 8080";
        }
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 9090;
          bindAddress = "172.28.13.156";
          extraArguments = "9090 192.168.1.79 9090";
        }
      ];
    };
    btrbk = {
      instances = {
        btrbk = {
          settings = {
            volume = {
              "ssh://max-nixos-workstation-zerotier/nexus" = {
                subvolume = {
                  "@NixOS" = {
                    snapshot_name = "@NixOS-for-pc";
                  };
                };
                target = "/HDD/backups/workstation";
                snapshot_preserve = "1d 1w";
                snapshot_preserve_min = "latest";
                incremental = "strict";
              };
              "ssh://max-nixos-workstation-zerotier/Big" = {
                subvolume = {
                  "shared" = {
                    snapshot_name = "shared-for-pc";
                  };
                };
                target = "/HDD/backups/workstation";
                snapshot_preserve = "1d 1w";
                snapshot_preserve_min = "latest";
                incremental = "strict";
              };
              "/nexus" = {
                target = {
                  "/HDD/backups/pc" = {};
                };
              };
            };
          };
        };
      };
    };
    dbus = {
      packages = [
        (pkgs.writeTextDir "share/dbus-1/system.d/dnsmasq-rootless.conf" ''
          <!DOCTYPE busconfig PUBLIC
           "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
           "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
          <busconfig>
                  <policy user="dnsmasq">
                          <allow own="uk.org.thekelleys.dnsmasq"/>
                          <allow send_destination="uk.org.thekelleys.dnsmasq"/>
                  </policy>
          </busconfig>
        '')
      ];
    };
    dnsmasq = {
      enable = true;
      resolveLocalQueries = true;
      settings = {
        bind-dynamic = true;
        dnssec = true;
        domain = "usb.home.arpa";
        dhcp-fqdn = true;
        dhcp-range = [ "192.168.2.20,192.168.2.250" ];
        conf-file =
          "${config.services.dnsmasq.package}/share/dnsmasq/trust-anchors.conf";
        except-interface = "lo";
        interface = "usb";
        no-hosts = true;
        dhcp-rapid-commit = true;
        server = ["127.0.0.1"];
        trust-anchor = [
          "max.home.arpa.,6286,16,2,E5D985578B9746BFE1C6FF47E87E27F9BE9942BF947C7AE18C448C86C303DB0E"
          "max.home.arpa.,5629,14,4,663B18A6E58159EA67190937115450B87C60222A4F8D13395ACF3B091CF6155E4BE365D636452E9427C7818866BE9D65"
        ];
      };
    };
    ollama = {
      enable = true;
      host = "172.28.13.156";
      acceleration = "cuda";
    };
    ratbagd = {
      enable = true;
    };
    unbound.settings.auth-zone = [
      {
        for-downstream = "no";
        name = ".";
        primary = [
          "199.9.14.201"         # b.root-servers.net
          "192.33.4.12"          # c.root-servers.net
          "199.7.91.13"          # d.root-servers.net
          "192.5.5.241"          # f.root-servers.net
          "192.112.36.4"         # g.root-servers.net
          "193.0.14.129"         # k.root-servers.net
          "192.0.47.132"         # xfr.cjr.dns.icann.org
          "192.0.32.132"         # xfr.lax.dns.icann.org
          "2001:500:200::b"      # b.root-servers.net
          "2001:500:2::c"        # c.root-servers.net
          "2001:500:2d::d"       # d.root-servers.net
          "2001:500:2f::f"       # f.root-servers.net
          "2001:500:12::d0d"     # g.root-servers.net
          "2001:7fd::1"          # k.root-servers.net
          "2620:0:2830:202::132" # xfr.cjr.dns.icann.org
          "2620:0:2d0:202::132"  # xfr.lax.dns.icann.org
        ];
        url = "https://www.internic.net/domain/root.zone";
        fallback-enabled = true;
        zonemd-check = true;
        zonefile = "/var/lib/unbound/root.zone";
      }
      {
        for-downstream = "no";
        name = "arpa";
        primary = [
          "199.9.14.201"         # b.root-servers.net
          "192.33.4.12"          # c.root-servers.net
          "199.7.91.13"          # d.root-servers.net
          "192.5.5.241"          # f.root-servers.net
          "192.112.36.4"         # g.root-servers.net
          "193.0.14.129"         # k.root-servers.net
          "192.0.47.132"         # xfr.cjr.dns.icann.org
          "192.0.32.132"         # xfr.lax.dns.icann.org
          "2001:500:200::b"      # b.root-servers.net
          "2001:500:2::c"        # c.root-servers.net
          "2001:500:2d::d"       # d.root-servers.net
          "2001:500:2f::f"       # f.root-servers.net
          "2001:500:12::d0d"     # g.root-servers.net
          "2001:7fd::1"          # k.root-servers.net
          "2620:0:2830:202::132" # xfr.cjr.dns.icann.org
          "2620:0:2d0:202::132"  # xfr.lax.dns.icann.org
        ];
        url = "https://www.internic.net/domain/arpa.zone";
        fallback-enabled = true;
        zonemd-check = true;
        zonefile = "/var/lib/unbound/arpa.zone";
      }
      {
        for-downstream = "no";
        name = "in-addr.arpa";
        url = "https://www.internic.net/domain/in-addr.arpa.zone";
        zonefile = "/var/lib/unbound/in-addr.arpa.zone";
      }
      {
        for-downstream = "no";
        name = "ip6.arpa";
        url = "https://www.internic.net/domain/ip6.arpa.zone";
        zonefile = "/var/lib/unbound/ip6.arpa.zone";
      }
      {
        for-downstream = "no";
        name = "root-servers.net";
        url = "https://www.internic.net/domain/root-servers.net.zone";
        zonefile = "/var/lib/unbound/root-servers.net.zone";
      }
    ];
    xserver = {
      displayManager.gdm.autoSuspend = false;
      videoDrivers = [
        "nvidia"
      ];
    };
  };
  systemd = {
    network = {
      enable = true;
      links = {
        "10-eno1" = {
          matchConfig = {
            MACAddress = "40:b0:76:de:79:dc";
          };
          linkConfig = {
            NamePolicy = "keep kernel database onboard slot path";
            AlternativeNamesPolicy = "database onboard slot path";
            GenericReceiveOffload = false;
            GenericSegmentationOffload = false;
            TCPSegmentationOffload = false;
          };
        };
        "10-usb" = {
          matchConfig.MACAddress = "00:e0:4c:37:03:20";
          linkConfig.Name = "usb";
        };
      };
      networks."10-usb" = {
        address = [ "192.168.2.1/24" ];
        DHCP = "no";
        matchConfig.MACAddress = "00:e0:4c:37:03:20";
        networkConfig = {
          ConfigureWithoutCarrier = true;
        };
      };
      wait-online.enable = lib.mkForce true;
    };
    services = {
      "3proxy" = {
        serviceConfig = {
          ProtectProc = "invisible";
          ProcSubset = "pid";
          DeviceAllow = "";
          ProtectHome = true;
          PrivateDevices = true;
          IPAddressDeny = "any";
          IPAddressAllow = "172.28.13.156/16 fd80:56c2:e21c:3d4b:c99:93d9:c2b9:c567/88 fc9c:6b89:eed9:c2b9:c567::1/40 192.168.1.79";
          ProtectKernelModules = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictNamespaces = true;
          CapabilityBoundingSet = "";
          RestrictRealtime = true;
          PrivateUsers = true;
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          LockPersonality = true;
          RestrictAddressFamilies = "AF_INET AF_INET6";
          ProtectKernelTunables = true;
          ProtectHostname = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          UMask = "0077";
        };
        confinement = {
          enable = true;
        };
      };
      btrbk-btrbk = {
        unitConfig = {
          RequiresMountsFor = "/HDD/backups";
        };
        serviceConfig = {
          BindPaths = [ "/HDD/backups" ];
          PrivateNetwork = lib.mkForce false;
          IPAddressAllow = "172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258 fc9c:6b89:eec5:0d88:e258:0000:0000:0001";
          RestrictSUIDSGID = lib.mkForce false;
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
      dnsmasq = {
        preStart = lib.mkForce "";
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          IPAddressAllow = "0.0.0.0 255.255.255.255 fe80::/10 ff02::1 127.0.0.1 fd80:1234::/64 192.168.2.0/24";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateUsers = lib.mkForce false;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = lib.mkForce "strict";
          RemoveIPC = true;
          RestrictNamespaces = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6 AF_NETLINK";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "dnsmasq";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          UMask = "0077";
          User = "dnsmasq";
          BindReadOnlyPaths = [
            "/etc/resolv.conf"
            "/etc/passwd"
            "/run/nscd"
            "/run/dbus/system_bus_socket"
            "/run/systemd/journal/dev-log"
          ];
        };
        confinement = {
          enable = true;
        };
      };
      unbound = {
        after = [ "zone-home-test.service" ];
        wants = [ "zone-home-test.service" ];
      };
    };
    tmpfiles = {
      rules = [
        "v /HDD/backups 700 btrbk btrbk"
        "d /HDD/backups/pc"
        "d /HDD/backups/workstation"
      ];
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
