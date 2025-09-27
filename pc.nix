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
  hardware.nvidia.open = true;
  networking = {
    firewall = {
      extraForwardRules = ''
        iifname tayga oifname shadow-lan accept
      '';
      filterForward = true;
      interfaces.ztmjfp7kiq.allowedTCPPorts = [ 8080 9090 11434 ];
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
    ollama = {
      enable = true;
      host = "172.28.13.156";
      acceleration = "cuda";
    };
    ratbagd = {
      enable = true;
    };
    unbound.settings = {
      forward-zone = {
        name = ".";
        forward-addr = [ "fd09:a389:7c1e:4::1@55" ];
        forward-first = true;
      };
      server = {
        domain-insecure = [ "broadband" ];
        qname-minimisation = false;
      };
      stub-zone = [
        {
          name = "max.home.arpa";
          stub-addr = [
            "172.28.10.244"
            "fc9c:6b89:eec5:d88:e258::1"
            "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258"
          ];
        }
      ];
    };
    xserver = {
      displayManager.gdm.autoSuspend = false;
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
          extraConfig = ''
            [VLAN]
            Id=20
            Protocol=802.1ad
          '';
          netdevConfig = {
            Kind = "vlan";
            Name = "shadow-lan";
          };
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
          DHCP = "ipv6";
          matchConfig.Name = "shadow-lan";
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
        wants = [ "sys-subsystem-net-devices-tayga.device" ];
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
    groups.tayga = {};
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
      tayga = {
        isSystemUser = true;
        group = "tayga";
      };
    };
  };

}
