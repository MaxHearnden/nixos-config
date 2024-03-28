{ lib, pkgs, config, inputs, ... }:

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
      device = config.fileSystems."/Big".device;
      options = config.fileSystems."/Big".options ++ [ "subvol=/shared" ];
      # options = ["x-systemd.requires=nfs-server.service"];
    };
    "/nexus" = {
      device = "/dev/disk/by-uuid/76463411-5c55-4708-bf63-7e3195776b57";
      fsType = "btrfs";
      options = [ "nofail" "defaults" "compress=zstd" "nosuid" "nodev" "noatime" ];
    };
  };
  # krb5 = {
  #   realms = {
  #     WORKSTATION = {
  #       master_key_type = "aes256-cts";
  #       supported_enctypes = "aes256-cts:normal aes128-cts:normal";
  #     };
  #   };
  # };
  nix = {
    distributedBuilds = true;
  };
  networking = {
    firewall = {
      interfaces = {
        ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 3000 2049 ];
        tailscale0 = {
          allowedTCPPorts = [ 22 ];
        };
        enp2s0 = {
          allowedTCPPorts = [ 5000 53 ];
          allowedUDPPorts = [ 53 69 ];
        };
      };
    };
    hostName = "max-nixos-workstation";
    hosts =
      lib.listToAttrs (
        lib.genList (index:
          lib.nameValuePair "192.168.2.1${toString (index + 1)}" [ "nixos-slot${toString (index + 1)}"]
        ) 7
      );
    interfaces = {
      enp2s0 = {
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
        "enp2s0"
      ];
    };
    networkmanager = {
      unmanaged = [
        "enp2s0"
      ];
    };
  };
  services = {
    _3proxy = {
      enable = true;
      services = [
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 3000;
          bindAddress = "max-nixos-workstation-zerotier-6plane";
          extraArguments = "3000 172.28.10.244 3000";
        }
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 3000;
          bindAddress = "max-nixos-workstation-zerotier-rfc4193";
          extraArguments = "3000 172.28.10.244 3000";
        }
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 5000;
          bindAddress = "192.168.2.1";
          extraArguments = "5000 max-nixos-workstation-zerotier 8080";
        }
      ];
    };
    btrbk = {
      extraPackages = [
        pkgs.zstd
      ];
      instances = {
        workstation = {
          settings = {
            volume = {
              "/nexus" = {
                target = "/Big/backups/workstation";
              };
              "/Big" = {
                subvolume = "shared";
                target = "/nexus/backups/workstation";
              };
            };
          };
        };
      };
      sshAccess = [
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEQQFWFgxHvO9V02h2V7Ylgiou9o745w08xBEddL7HA0 btrbk@max-nixos-pc";
          roles = [
            "receive"
            "delete"
            "source"
          ];
        }
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6GaQD1sg32My+wRYROof6BrFX5XoFDe+f/aggoRUMR btrbk@max-nixos-chromebooksd2";
          roles = [
            "receive"
            "delete"
          ];
        }
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ62a5GL8BnuwriNuk2TamZdnfxAiGTXLQOby88zS3Br btrbk@max-nixos-dell";
          roles = [
            "receive"
            "delete"
          ];
        }
      ];
    };
    gitea = {
      database.type = "postgres";
      enable = true;
      settings = {
        security = {
          DISABLE_GIT_HOOKS = true;
        };
        server = {
          DOMAIN = "max-nixos-workstation-zerotier";
          HTTP_ADDR = "172.28.10.244";
        };
        service = {
          DISABLE_REGISTRATION = true;
        };
      };
    };
    harmonia = {
      enable = true;
      signKeyPath = "/etc/nix/storekey";
      settings = {
        bind = "max-nixos-workstation-zerotier:8080";
        priority = 50;
      };
    };
    # hydra = {
    #   buildMachinesFiles = ["/hydra-machines"];
    #   enable = true;
    #   extraConfig = ''
    #     binary_cache_secret_key_file = /etc/nix/storekey
    #     max_output_size = 8000000000
    #     Include /var/lib/hydra/gitea_authorisations.conf
    #   '';
    #   hydraURL = "http://172.28.10.244:8080";
    #   listenHost = "172.28.10.244";
    #   notificationSender = "hydra@example.com";
    #   port = 8080;
    #   useSubstitutes = true;
    # };
    kea = {
      dhcp4 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = [
              "enp2s0"
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
    nfs = {
      server = {
        enable = true;
        hostName = "max-nixos-workstation-zerotier,192.168.2.1";
        exports = ''
          /Big/shared -mp=/Big,rw,all_squash,anonuid=1000,anongid=100,async max-nixos-* max-guix-*
          /Big/shared/riscv/star64_root 192.168.2.0/24(rw,no_root_squash,mp=/Big)
          /nix 192.168.2.0/24(ro,no_root_squash)
        '';
      };
    };
    # nix-serve = {
    #   bindAddress = "192.168.2.1";
    #   enable = true;
    #   # openFirewall = true;
    #   secretKeyFile = "/etc/nix/storekey";
    # };
    ratbagd = {
      enable = true;
    };
    xserver = {
      autorun = false;
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
        sessionCommands = "xhost +SI:localuser:max";
      };
    };
  };
  systemd = {
    # network = {
    #   enable = true;
    #   networks = {
    #     "10-enp2s0" = {
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
    #         Name = "enp2s0";
    #       };
    #       networkConfig = {
    #         DHCPServer = true;
    #       };
    #     };
    #   };
    #   wait-online = {
    #     ignoredInterfaces = [
    #       "enp2s0"
    #     ];
    #   };
    # };
    services = {
      "3proxy" = {
        serviceConfig = {
          ProtectProc = "invisible";
          ProcSubset = "pid";
          DeviceAllow = "";
          ProtectHome = true;
          PrivateDevices = true;
          IPAddressDeny = "any";
          IPAddressAllow = "172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258/88 fc9c:6b89:eec5:0d88:e258:0000:0000:0001/40 192.168.2.1/24";
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
      };
      btrbk-workstation = {
        serviceConfig = {
          BindPaths = [ "/Big" ];
          PrivateNetwork = true;
          RestrictAddressFamilies = "AF_UNIX";
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
      harmonia = {
        wants = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" "nss-lookup.target" ];
        serviceConfig = {
          RestrictSUIDSGID = true;
          RemoveIPC = true;
        };
        after = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" "nss-lookup.target" ];
      };
      latest-system = {
        serviceConfig = {
          ExecStart = "${inputs.latest-system.packages.x86_64-linux.default}/bin/latest-system-systemd --protocol activate";
          CapabilityBoundingSet = null;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictAddressFamilies = "none";
          # PrivateDevices = true;
          UMask = "0077";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          BindReadOnlyPaths = "/nix/var/nix/profiles/all";
          SystemCallArchitectures = "native";
          ProtectClock = true;
          ProtectKernelLogs = true;
          PrivateNetwork = true;
          MemoryDenyWriteExecute = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          RestrictRealtime = true;
          RemoveIPC = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          ProtectHome = true;
          IPAddressDeny = "any";
          # RootDirectory = "/var/empty";
          # MountAPIVFS = true;
          # RootEphemeral = true;
        };
        confinement = {
          enable = true;
        };
        requires = [ "latest-system.socket" ];
        serviceConfig = {
          Restart = "always";
          User = "latest-system";
          Group = "latest-system";
        };
      };
      # nix-serve = {
      #   serviceConfig = {
      #     Restart = "always";
      #     CapabilityBoundingSet = null;
      #     NoNewPrivileges = true;
      #     RestrictNamespaces = true;
      #     RestrictAddressFamilies = "AF_INET AF_UNIX";
      #     RootDirectory = "/var/empty";
      #     TemporaryFileSystem = "/";
      #     PrivateTmp = true;
      #     MountAPIVFS = true;
      #     ProtectProc = "invisible";
      #     ProcSubset = "pid";
      #     BindReadOnlyPaths = "/bin/sh /nix/store /nix/var/nix/daemon-socket/socket";
      #     PrivateDevices = true;
      #     PrivateMounts = true;
      #     ProtectSystem = false;
      #     DynamicUser = lib.mkForce false;
      #     RemoveIPC = true;
      #     ProtectClock = true;
      #     ProtectKernelLogs = true;
      #     ProtectControlGroups = true;
      #     ProtectKernelModules = true;
      #     SystemCallArchitectures = "native";
      #     MemoryDenyWriteExecute = true;
      #     RestrictSUIDSGID = true;
      #     ProtectHostname = true;
      #     LockPersonality = true;
      #     ProtectKernelTunables = true;
      #     RestrictRealtime = true;
      #     ProtectHome = true;
      #     PrivateUsers = true;
      #     SystemCallFilter = [ "@system-service" "~@resources" ];
      #     IPAddressAllow = [ "172.28.0.0/16" "192.168.2.0/24" ];
      #     IPAddressDeny = "any";
      #     UMask = "0077";
      #   };
      # };
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
          config_all="$(nix build git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-config --no-link --print-out-paths --refresh --recreate-lock-file --no-write-lock-file)"
          nix-env -p /nix/var/nix/profiles/all --set "''${config_all}"
          systemctl stop latest-system.service
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
      # ntpd = {
      #   serviceConfig = {
      #     # CapabilityBoundingSet = "CAP_SYS_TIME CAP_NET_BIND_SERVICE";
      #     # SystemCallFilter = [ "@system-service @clock" "~@resources" ];
      #     BindPaths = "/var/lib/ntp";
      #     BindReadOnlyPaths = "/etc /var/run/nscd"; #services /etc/localtime /etc/nsswitch.conf /etc/resolv.conf";
      #     UMask = "0755";
      #     DeviceAllow = "/dev/log";
      #     ExecStart =
      #       let cfg = config.services.ntp;
      #           configFile = pkgs.writeText "ntp.conf" ''
      #             driftfile /var/lib/ntp/ntp.drift

      #             restrict default ${toString cfg.restrictDefault}
      #             restrict -6 default ${toString cfg.restrictDefault}
      #             restrict source ${toString cfg.restrictSource}

      #             restrict 127.0.0.1
      #             restrict -6 ::1

      #             ${toString (map (server: "server " + server + " iburst\n") cfg.servers)}

      #             ${cfg.extraConfig}
      #           '';
      #       in
      #     # lib.mkForce "${pkgs.strace}/bin/strace -f ${pkgs.ntp}/bin/ntpd -g -c ${configFile} -u ntp:ntp";
      #     lib.mkForce "${pkgs.coreutils}/bin/cat /proc/mounts";
      #   };
      #   preStart = lib.mkForce "";
      #   confinement = {
      #     enable = true;
      #   };
      # };
      postgresql = {
        serviceConfig =
          let hosts = builtins.toFile "hosts" ''
            127.0.0.1 localhost
            ::1 localhost
          ''; in {
          BindReadOnlyPaths = "${hosts}:/etc/hosts /etc/passwd";
          NoNewPrivileges = true;
          PrivateUsers = lib.mkForce false;
          PrivateNetwork = true;
          CapabilityBoundingSet = "";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          ProtectProc = "invisible";
          ProcSubset = "pid";
          ProtectHome = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          MemoryDenyWriteExecute = true;
          Environment = [ "XDG_DATA_DIRS=${config.services.postgresql.package}/share" ];
          RemoveIPC = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          ProtectKernelModules = true;
          IPAddressAllow = "localhost";
          IPAddressDeny = "any";
          RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6";
          RestrictRealtime = true;
          LockPersonality = true;
          ProtectHostname = true;
        };
        confinement = {
          enable = true;
          packages = [ config.i18n.glibcLocales ];
        };
      };
    };
    sockets = {
      latest-system = {
        listenStreams = ["172.28.10.244:8081" "[fd80:56c2:e21c:3d4b:c99:93c5:d88:e258]:8081" "[fc9c:6b89:eec5:d88:e258::1]:8081"];
        socketConfig = {
          FreeBind = true;
          IPAddressAllow = "172.28.0.0/16 fd80:56c2:e21c:3d4b:c99:9300::/88 fc9c:6b89:ee00::/40";
          IPAddressDeny = "any";
        };
        wantedBy = [ "multi-user.target" ];
      };
    };
    timers = {
      nixos-upgrade-all = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
    tmpfiles = {
      rules = [
        "d /Big/snapshots/btrbk - btrbk btrbk"
        "v /Big/backups 700 btrbk btrbk"
        "d /Big/backups/pc"
        "d /Big/backups/dell"
        "d /Big/backups/chromebooksd2"
        "d /Big/backups/laptop"
        "d /Big/backups/workstation - btrbk btrbk"
        "v /nexus/backups 700 btrbk btrbk"
        "d /nexus/backups/workstation - btrbk btrbk"
        "a /Big/shared - - - - u:btrbk:rx,g::-,m::rx"
      ];
    };
  };
  users = {
    groups = {
      latest-system = {};
      # nix-serve = {};
    };
    users = {
      btrbk = {
        packages = with pkgs; [
          zstd
        ];
      };
      latest-system = {
        isSystemUser = true;
        group = "latest-system";
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
      # nix-serve = {
      #   isSystemUser = true;
      #   group = "nix-serve";
      # };
    };
  };
}
