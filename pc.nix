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
      }) [ "650-systemd-boot.pcrlock" "670-kernel.pcrlock"
      "705-kernel-cmdline.pcrlock" "710-kernel-cmdline.pcrlock"
      "720-kernel-initrd.pcrlock" ])
      // {
        "dnsdist/dnsdist.conf".text = ''
          -- listen on local addresses
          addLocal("127.0.0.1:53")
          addLocal("[::]:53")

          newServer({
            address = "[::1]:54",
            name = "knot",
            pool = "auth",
            healthCheckMode = "lazy"
          })
          newServer({
            address = "[::1]:55",
            name = "unbound",
            pool = "recursive",
            healthCheckMode = "lazy"
          })

          addAction(RDRule(), PoolAction("recursive"))
          addAction(AllRule(), PoolAction("auth"))
        '';
        "tayga/tayga.conf".text = ''
          tun-device tayga
          ipv4-addr 192.0.0.2
          ipv6-addr fd64::1
          map 192.0.0.1 fd64::2
          prefix fd09:a389:7c1e:3::/64
        '';
        "tayga/plat.conf".text = ''
          tun-device plat
          ipv4-addr 192.168.12.3
          prefix fc9c:6b89:eed9:c2b9:c567:1::/96
        '';
      };
  };
  hardware = {
    graphics.extraPackages = [
      pkgs.intel-media-driver
      pkgs.nvidia-vaapi-driver
    ];
    nvidia.open = true;
  };
  networking = {
    firewall = {
      allowedTCPPorts = [ 54 8053 ];
      allowedUDPPorts = [ 54 8053 ];
      extraForwardRules = ''
        iifname tayga oifname shadow-lan accept
        iifname ztmjfp7kiq oifname plat accept
      '';
      filterForward = true;
      interfaces = {
        eno1 = {
          allowedTCPPorts = [ 9943 9944 ];
          allowedUDPPorts = [ 9943 9944 ];
        };
        ztmjfp7kiq.allowedTCPPorts = [ 8080 9090 11434 ];
      };
    };
    hostName = "max-nixos-pc";
    nat = {
      enable = true;
      externalInterface = "eno1";
      internalInterfaces = [ "plat" ];
    };
    networkmanager.enable = false;
    nftables.tables.tayga-nat66 = {
      family = "ip6";
      content = ''
        chain tayga-nat {
          type nat hook postrouting priority srcnat; policy accept
          iifname tayga oifname shadow-lan masquerade
          iifname ztmjfp7kiq oifname plat snat ip6 to [fc9c:6b89:eed9:c2b9:c567:1:c0a8:d00]/120
        }
      '';
    };
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
              "ssh://workstation.zandoodle.me.uk/nexus" = {
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
              "ssh://workstation.zandoodle.me.uk/Big" = {
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
    displayManager.gdm.autoSuspend = false;
    knot = {
      enable = true;
      settings = {
        acl.transfer = {
          action = "transfer";
          address = [
            "10.0.0.0/8"
            "100.64.0.0/10"
            "127.0.0.0/8"
            "169.254.0.0/16"
            "192.168.0.0/16"
            "172.16.0.0/12"
            "::1/128"
            "fc00::/7"
            "fe80::/10"
          ];
        };
        mod-queryacl.local.address = [
          "10.0.0.0/8"
          "100.64.0.0/10"
          "127.0.0.0/8"
          "169.254.0.0/16"
          "192.168.0.0/16"
          "172.16.0.0/12"
          "::1/128"
          "fc00::/7"
          "fe80::/10"
        ];
        remote.orion.address = [
          "fd7a:115c:a1e0::1a01:5208@54"
          "100.122.82.8@54"
        ];
        server = {
          automatic-acl = true;
          identity = "pc.zandoodle.me.uk";
          listen = [ "0.0.0.0@8053" "::@8053" "0.0.0.0@54" "::@54" ];
          nsid = "pc.zandoodle.me.uk";
          tcp-fastopen = true;
          tcp-reuseport = true;
        };
        template = {
          catalog-zone = {
            acl = [ "transfer" ];
            master = "orion";
            module = "mod-queryacl/local";
            semantic-checks = true;
          };
          global = {
            acl = [ "transfer" ];
            dnssec-validation = true;
            master = "orion";
            semantic-checks = true;
            zonemd-verify = true;
          };
          default.global-module = ["mod-cookies" "mod-rrl"];
        };
        zone.catz = {
          master = "orion";
          catalog-role = "interpret";
          catalog-template = ["catalog-zone" "global"];
        };
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
    unbound.settings = {
      forward-zone = [
        {
          name = ".";
          forward-addr = [ "fd09:a389:7c1e:1::1@55" "192.168.1.201@55" ];
          forward-first = true;
        }
        {
          name = "broadband";
          forward-addr = [ "192.168.1.1" ];
        }
      ];
      server = {
        domain-insecure = [
          "broadband"
          "home.arpa"
          "168.192.in-addr.arpa"
          "d.f.ip6.arpa"
        ];
        interface = [ "127.0.0.1@55" "::@55" ];
        local-zone = [
          "168.192.in-addr.arpa nodefault"
          "d.f.ip6.arpa nodefault"
        ];
        qname-minimisation = false;
      };
      stub-zone = [
        {
          name = "max.home.arpa";
          stub-host = "workstation.zandoodle.me.uk";
        }
      ];
    };
    xserver = {
      videoDrivers = [
        "nvidia"
      ];
    };
  };
  systemd = {
    network = {
      config.networkConfig.IPv6Forwarding = true;
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
      };
      netdevs = {
        "10-shadow-lan" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "shadow-lan";
          };
          vlanConfig.Id = 20;
        };
        "10-tayga" = {
          netdevConfig = {
            Kind = "tun";
            Name = "tayga";
          };
          tunConfig = {
            Group = "tayga";
            User = "tayga";
          };
        };
        "10-plat" = {
          netdevConfig = {
            Kind = "tun";
            Name = "plat";
          };
          tunConfig = {
            Group = "tayga";
            User = "tayga";
          };
        };
      };
      networks = {
        "10-eno1" = {
          DHCP = "yes";
          matchConfig.Name = "eno1";
          networkConfig.IPv6AcceptRA = true;
          vlan = [ "shadow-lan" ];
        };
        "10-shadow-lan" = {
          DHCP = "yes";
          dhcpV4Config.RouteMetric = 1536;
          ipv6AcceptRAConfig.RouteMetric = 2048;
          name = "shadow-lan";
          networkConfig.IPv6AcceptRA = true;
        };
        "10-tayga" = {
          address = [ "192.0.0.1/30" "fd64::/64" ];
          matchConfig.Name = "tayga";
          routes = [
            {
              Destination = "0.0.0.0/0";
              Metric = 2048;
              MTUBytes = 1480;
            }
          ];
        };
        "10-plat" = {
          address = [ "192.168.12.1/24" "fc9c:6b89:eed9:c2b9:c567:1:192.168.12.2/96" ];
          matchConfig.Name = "plat";
          routes = [
            {
              Destination = "192.168.13.0/24";
              Metric = 2048;
              MTUBytes = 1480;
            }
          ];
        };
      };
      wait-online.enable = lib.mkForce true;
    };
    packages = [
      pkgs.dnsdist
    ];
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
          IPAddressAllow = "::1 127.0.0.1 100.91.224.22 fd7a:115c:a1e0:ab12:4843:cd96:625b:e016";
          RestrictSUIDSGID = lib.mkForce false;
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
      dnsdist = {
        serviceConfig = {
          # Override the dnsdist service to use /etc/dnsdist/dnsdist.conf
          ExecStart = [
            ""
            "${lib.getExe pkgs.dnsdist} --supervised --disable-syslog --config /etc/dnsdist/dnsdist.conf"
          ];
          ExecStartPre = [
            ""
            "${lib.getExe pkgs.dnsdist} --check-config --config /etc/dnsdist/dnsdist.conf"
          ];

          # Run as a dedicated user
          User = "dnsdist";
          Group = "dnsdist";
        };

        # Restart dnsdist when the config changes
        restartTriggers = [ config.environment.etc."dnsdist/dnsdist.conf".source ];

        # Restart dnsdist immediatly
        startLimitIntervalSec = 0;

        # Start dnsdist on boot
        wantedBy = [ "multi-user.target" ];
      };
      plat = {
        after = [ "sys-subsystem-net-devices-plat.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/plat.conf".source ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."tayga/plat.conf".source}:/etc/tayga/plat.conf"
            "/dev/net/tun"
          ];
          CapabilityBoundingSet = "";
          DeviceAllow = "/dev/net/tun";
          ExecStart = "${lib.getExe pkgs.tayga} -d -c /etc/tayga/plat.conf";
          Group = "tayga";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          Restart = "on-failure";
          RestrictAddressFamilies = "AF_INET";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "tayga";
        };
        wantedBy = [ "multi-user.target" ];
        wants = [ "sys-subsystem-net-devices-plat.device" ];
      };
      tayga = {
        after = [ "sys-subsystem-net-devices-tayga.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/tayga.conf".source ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."tayga/tayga.conf".source}:/etc/tayga/tayga.conf"
            "/dev/net/tun"
          ];
          CapabilityBoundingSet = "";
          DeviceAllow = "/dev/net/tun";
          ExecStart = "${lib.getExe pkgs.tayga} -d -c /etc/tayga/tayga.conf";
          Group = "tayga";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          Restart = "on-failure";
          RestrictAddressFamilies = "AF_INET";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "tayga";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "tayga";
        };
        wantedBy = [ "multi-user.target" ];
        wants = [ "sys-subsystem-net-devices-tayga.device" ];
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
    groups = {
      dnsdist = {};
      tayga = {};
    };
    users = {
      btrbk = {
        packages = with pkgs; [
          zstd
        ];
      };
      dnsdist = {
        group = "dnsdist";
        isSystemUser = true;
      };
      max = {
        extraGroups = [ "knot" ];
        packages = with pkgs; [
          piper
        ];
      };
      tayga = {
        isSystemUser = true;
        group = "tayga";
      };
    };
  };

}
