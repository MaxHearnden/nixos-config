{ pkgs, config, inputs, ... }:

{
  imports = [./configuration.nix ./hardware-configuration/workstation.nix];
  boot = {
    # loader = {
    #   grub = {
    #     default = 3;
    #   };
    # };
    tmp = {
      tmpfsSize = "100%";
    };
  };
  environment = {
    etc = {
      "nix/machines" = {
        source = "/machines";
      };
    };
    systemPackages = with pkgs; [
      gtk3
      (
        pkgs.writeShellScriptBin "ssh-mac"
        ''
          exec ssh -a -x -C max@172.28.31.224 /nix/var/nix/profiles/default/bin/nix-daemon "$@"
        ''
      )
      (
        pkgs.writeShellScriptBin "ssh-mac-x86"
        ''
          exec ssh -a -x -C max@172.28.226.152 /nix/var/nix/profiles/default/bin/nix-daemon "$@"
        ''
      )
    ];
  };
  fileSystems = {
    "/home/max/shared" = {
      options = ["x-systemd.after=nfs-server.service"];
    };
  };
  krb5 = {
    realms = {
      WORKSTATION = {
        master_key_type = "aes256-cts";
        supported_enctypes = "aes256-cts:normal aes128-cts:normal";
      };
    };
  };
  nix = {
    distributedBuilds = true;
  };
  networking = {
    firewall = {
      interfaces = {
        ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 3000 2049 ];
        enp1s0 = {
          allowedTCPPorts = [ 53 ];
          allowedUDPPorts = [ 53 69 ];
        };
      };
    };
    hostName = "max-nixos-workstation";
    interfaces = {
      enp1s0 = {
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
      externalInterface = "eno1";
      internalInterfaces = [
        "enp1s0"
      ];
    };
    networkmanager = {
      unmanaged = [
        "enp1s0"
      ];
    };
  };
  services = {
    gitea = {
      database.type = "postgres";
      enable = true;
      settings = {
        security = {
          DISABLE_GIT_HOOKS = true;
        };
        server = {
          DOMAIN = "172.28.10.244";
          HTTP_ADDR = "172.28.10.244";
        };
        service = {
          DISABLE_REGISTRATION = true;
        };
      };
    };
    hydra = {
      buildMachinesFiles = ["/hydra-machines"];
      enable = true;
      extraConfig = ''
        binary_cache_secret_key_file = /etc/nix/storekey
        max_output_size = 8000000000
        Include /var/lib/hydra/gitea_authorisations.conf
      '';
      hydraURL = "http://172.28.10.244:8080";
      listenHost = "172.28.10.244";
      notificationSender = "hydra@example.com";
      port = 8080;
      useSubstitutes = true;
    };
    kerberos_server = {
      enable = true;
      realms."WORKSTATION" = {};
    };
    kea = {
      dhcp4 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = [
              "enp1s0"
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
                  pool = "192.168.2.10 - 192.168.2.240";
                }
              ];
              subnet = "192.168.2.0/24";

              option-data = [
                {
                  name = "routers";
                  data = "192.168.2.1";
                }
              ];
            }
          ];
        };
      };
    };
    nfs = {
      server = {
        enable = true;
        hostName = "172.28.10.244,192.168.2.1";
        exports = ''
          /Big/shared -mp=/Big,rw,all_squash,anonuid=1000,anongid=100,async max-nixos-* max-guix-*
          /Big/shared/riscv/star64_root 192.168.2.0/24(rw,no_root_squash,mp=/Big)
          /nix 192.168.2.0/24(ro,no_root_squash)
        '';
      };
    };
    nix-serve = {
      bindAddress = "192.168.2.1";
      enable = true;
      openFirewall = true;
      secretKeyFile = "/etc/nix/storekey";
    };
    ratbagd = {
      enable = true;
    };
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
        sessionCommands = "xhost +SI:localuser:max";
      };
      xrandrHeads = [ "HDMI-3" "HDMI-2" ];
    };
  };
  systemd = {
    # network = {
    #   enable = true;
    #   networks = {
    #     "10-enp1s0" = {
    #       address = ["192.168.2.1/24"];
    #       dhcpServerConfig = {
    #         EmitDNS = false;
    #         PoolOffset = 10;
    #         PoolSize = 240;
    #       };
    #       dhcpServerStaticLeases = [
    #         {
    #           dhcpServerStaticLeaseConfig = {
    #             MACAddress = "d4:93:90:06:43:76";
    #             Address = "192.168.2.2";
    #           };
    #         }
    #       ];
    #       matchConfig = {
    #         Name = "enp1s0";
    #       };
    #       networkConfig = {
    #         DHCPServer = true;
    #       };
    #     };
    #   };
    #   wait-online = {
    #     ignoredInterfaces = [
    #       "enp1s0"
    #     ];
    #   };
    # };
    services = {
      latest-system = {
        serviceConfig = {
          ExecStart = "${inputs.latest-system.packages.x86_64-linux.default}/bin/latest-system";
          CapabilityBoundingSet = null;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictAddressFamilies="AF_INET";
          # PrivateDevices = true;
          UMask = "0077";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          BindReadOnlyPaths = "/nix/var/nix/profiles/all";
          SystemCallArchitectures = "native";
          ProtectClock = true;
          ProtectKernelLogs = true;
          MemoryDenyWriteExecute = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          RestrictRealtime = true;
          RemoveIPC = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          ProtectHome = true;
          # RootDirectory = "/var/empty";
          # MountAPIVFS = true;
          # RootEphemeral = true;
        };
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        requires = [ "network-online.target" ];
        confinement = {
          enable = true;
        };
        serviceConfig = {
          Restart = "always";
          User = "latest-system";
          Group = "latest-system";
        };
      };
      nixos-upgrade-all = {
        after = [ "network-online.target" "gitea.service" ];
        description = "NixOS upgrade all";
        path = with pkgs; [
          coreutils
          gnutar
          xz.bin
          gzip
          gitMinimal
          config.nix.package.out
          config.programs.ssh.package
          systemd
        ];
        restartIfChanged = false;
        script = ''
          config_all="$(nix build git+http://172.28.10.244:3000/zandoodle/nixos-config --no-link --print-out-paths --refresh --recreate-lock-file --no-write-lock-file)"
          nix-env -p /nix/var/nix/profiles/all --set "''${config_all}"
          systemctl restart latest-system.service
          config="$(readlink -e "''${config_all}/${config.networking.hostName}")"
          nix-env -p /nix/var/nix/profiles/system --set "''${config}"
          if [ "$1" = --specialisation ]
          then
            "''${config}/bin/switch-to-configuration" boot
            "''${config}/specialisation/$2/switch-to-configuration" test
          else
            "''${config}/bin/switch-to-configuration" switch
          fi
        '';
        startAt = "17:45";
        unitConfig = {
          X-StopOnRemoval = false;
        };
        wants = [ "network-online.target" "gitea.service" ];
      };
    };
    timers = {
      nixos-upgrade-all = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
  };
  users = {
    groups.latest-system = {};
    users = {
      latest-system = {
        isSystemUser = true;
        group = "latest-system";
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
    };
  };
}
