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
      interfaces = {
        ztmjfp7kiq = {
          allowedTCPPorts = [ 8080 9090 11434 ];
        };
      };
    };
    hostName = "max-nixos-pc";
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
    ollama = {
      enable = true;
      host = "172.28.13.156";
      acceleration = "cuda";
    };
    ratbagd = {
      enable = true;
    };
    unbound = {
      localControlSocketPath = "/run/unbound/unbound.ctl";
      settings = {
        server = {
          local-zone = "home.arpa. transparent";
          trust-anchor-file = map (key: "/var/lib/zone/home-test/${key}/.ds")
          (lib.attrNames config.services.zones.home-test.ksks);
        };
        auth-zone = {
          name = "max.home.arpa";
          zonemd-check = true;
          zonefile = "/run/zone/home-test/zonefile";
        };
      };
    };
    xserver = {
      displayManager.gdm.autoSuspend = false;
      videoDrivers = [
        "nvidia"
      ];
    };
    zones.home-test = {
      zskAlgorithms = ["ed448" "ecdsap384sha384"];
      domain = "max.home.arpa.";
      ksks = {
        test-1 = "ed448";
        test-2 = "ecdsap384sha384";
      };
      signzoneArgs = "-u -n -b -z sha512";
      instances.zonefile.zone = ''
        max.home.arpa. SOA dns.max.home.arpa. . 0 7200 60 ${toString (2 * 24 * 60 * 60)} 1800
        workstation CNAME zerotier.workstation
        zerotier.workstation A 172.28.10.244
        zerotier.workstation AAAA fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258
        zerotier.workstation AAAA fc9c:6b89:eec5:0d88:e258:0000:0000:0001
        tailscale.workstation A 100.91.224.22
        tailscale.workstation AAAA fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
        minecraft DNAME workstation
        minecraft A 100.91.224.22
        minecraft AAAA fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
        gitea CNAME workstation
        chromebook CNAME zerotier.chromebook
        zerotier.chromebook A 172.28.156.146
        zerotier.chromebook AAAA fc9c:6b89:ee1a:7a70:b542:0000:0000:0001
        zerotier.chromebook AAAA fd80:56c2:e21c:3d4b:0c99:931a:7a70:b542
        label.label.label.test TXT "test entry"
      '';
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
