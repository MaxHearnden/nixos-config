{ inputs, lib, pkgs, config, ... }:

{
  imports = [./configuration.nix];
  fileSystems = {
    "/home/max/shared" = {
      device = "max-nixos-workstation-zerotier:/Big/shared";
      fsType = "nfs";
      options = [
        "defaults"
        "x-systemd.requires=sys-devices-virtual-net-ztmjfp7kiq.device"
        "x-systemd.requires=zerotierone.service"
        "x-systemd.automount"
        "x-systemd.idle-timeout=5m"
        "nofail"
        "noatime"
        "nofsc"
        "softreval"
        "async"
        "nodev"
        "nosuid"
      ];
    };
  };
  networking.resolvconf.extraConfig = ''
    search_domains=max.home.arpa
  '';
  nix = {
    settings = {
      trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
      substituters = ["http://max-nixos-workstation-zerotier:8080"];
    };
  };
  services = {
    btrbk = {
      instances = {
        btrbk = {
          settings = {
            backend_remote = "btrfs-progs-doas";
            volume = {
              "/nexus" = {
                target = {
                  "ssh://max-nixos-workstation-zerotier/Big/backups/${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}" = {};
                };
              };
            };
          };
        };
      };
    };
    unbound.settings = {
      stub-zone = lib.mkIf (config.networking.hostName != "max-nixos-pc") [
        {
          name = "home.arpa";
          stub-addr = [
            "172.28.10.244"
            "fc9c:6b89:eec5:d88:e258::1"
            "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258"
          ];
        }
      ];
    };
  };
  systemd = {
    network = {
      enable = true;
      networks = {
        "10-sl" = {
          matchConfig = {
            Name = "sl*";
          };
          DHCP = "yes";
          linkConfig = {
            RequiredForOnline = false;
          };
          networkConfig = {
            DNSSEC = true;
          };
          dhcpV4Config = {
            UseMTU = true;
          };
        };
      };
      wait-online = {
        enable = false;
      };
    };
    services = {
      "btrbk-btrbk" = {
        wants = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" ];
        after = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" ];
        serviceConfig = {
          RestrictSUIDSGID = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
          PrivateNetwork = true;
          BindReadOnlyPaths = [ "/run/nscd" ];
          ExecStart = lib.mkForce "${pkgs.btrbk}/bin/btrbk -c /etc/btrbk/btrbk.conf snapshot --preserve";
          Restart = "on-failure";
        };
        unitConfig = {
          OnSuccess = "btrbk-backup-btrbk.service";
        };
      };
      "btrbk-backup-btrbk" =
        let cfg = config.systemd.services."btrbk-btrbk";
        in {
          inherit (cfg) wants after confinement restartIfChanged;
          path = lib.mkForce cfg.path;
          serviceConfig = lib.removeAttrs cfg.serviceConfig ["RootDirectory" "InaccessiblePaths" "ReadOnlyPaths" "RuntimeDirectory"] // {
            IPAddressAllow = "172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258 fc9c:6b89:eec5:0d88:e258:0000:0000:0001";
            PrivateNetwork = [];
            ExecStartPre = "${pkgs.btrbk}/bin/btrbk clean";
            ExecStart = "${pkgs.btrbk}/bin/btrbk -c /etc/btrbk/btrbk.conf resume";
          };
          unitConfig = cfg.unitConfig // {
            OnSuccess = [];
          };
        };
      "nixos-upgrade" = {
        after = [ "network-online.target" "zerotierone.service" ];
        description = "NixOS Upgrade";
        enableStrictShellChecks = true;
        serviceConfig = {
          Type = "oneshot";
          RestartSec = 10;
          Restart = "on-failure";
        };
        path = with pkgs; [
          config.nix.package.out
          kexec-tools
        ];
        requires = [ "network-online.target" "zerotierone.service" ];
        restartIfChanged = false;
        script = ''
          set -x

          config="$(${pkgs.bind.dnsutils}/bin/delv -a /etc/home.bind.keys \
          +root=max.home.arpa +short @dns.max.home.arpa \
          "${config.networking.hostName}".systems.max.home.arpa TXT | tail -c \
          +2 | head -c -2)"

          ${config.nix.package}/bin/nix-env -p /nix/var/nix/profiles/system --set "''${config}"

          booted=$(readlink -e "/run/booted-system/kernel" "/run/booted-system/kernel-modules")
          current=$(readlink -e "$config/kernel" "$config/kernel-modules")
          if [ "$booted" != "$current" ]; then
            "$config/bin/switch-to-configuration" boot
            ${inputs.nixos-kexec.packages.x86_64-linux.default}/bin/nixos-kexec --when "+1d"
          else
            "$config/bin/switch-to-configuration" switch
          fi
        '';
        unitConfig = {
          X-StopOnRemoval = false;
        };
      };
      "slattach@" = {
        confinement = {
          enable = true;
        };
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_ADMIN";
          BindPaths = "%I";
          CapabilityBoundingSet = "CAP_NET_ADMIN";
          DeviceAllow = "%I";
          DynamicUser = true;
          ExecStart = "${lib.getBin pkgs.nettools}/bin/slattach -L -s 115200 %I";
          Group = "dialout";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          PrivateUsers = lib.mkForce false;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          RestrictAddressFamilies = "none";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = ["@system-service" "~@privileged @resources"];
          Type = "exec";
          UMask = "077";
          User = "slattach";
        };
      };
    };
    timers = {
      nixos-upgrade = {
        timerConfig = {
          OnBootSec = "0";
          OnUnitActiveSec = "1d";
        };
        wantedBy = [ "timers.target" ];
      };
    };
    tmpfiles = {
      rules = [
        "a+ /nix/var/nix/profiles - - - - u:nixos-upgrade:rwx"
        "A+ /boot - - - - u:nixos-upgrade:rwx,d:u:nixos-upgrade:rwx,m::rwx,d:m::rwx"
        "d /run/nixos 755 nixos-upgrade nixos-upgrade"
      ];
    };
  };
  users = {
    groups = {
      nixos-upgrade = {};
    };
    users = {
      nixos-upgrade = {
        group = "nixos-upgrade";
        extraGroups = [ "disk" ];
        isSystemUser = true;
      };
    };
  };
}
