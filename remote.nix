{ lib, pkgs, config, ... }:

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
        "fsc"
        "softreval"
        "async"
        "nodev"
        "nosuid"
      ];
    };
    "/boot" = {
      options = [
        "uid=nixos-upgrade"
        "gid=nixos-upgrade"
      ];
    };
  };
  nix = {
    buildMachines = [
      {
        hostName = "max-nixos-workstation-zerotier?remote-program=/run/current-system/sw/bin/ssh-mac-x86";
        maxJobs = 4;
        protocol = "ssh-ng";
        sshUser = "root";
        supportedFeatures = [
          "big-parallel"
          "benchmark"
        ];
        systems = ["x86_64-darwin"];
      }
      {
        hostName = "max-nixos-workstation-zerotier?remote-program=/run/current-system/sw/bin/ssh-mac";
        maxJobs = 8;
        protocol = "ssh-ng";
        sshUser = "root";
        supportedFeatures = [
          "big-parallel"
          "benchmark"
        ];
        systems = ["aarch64-darwin"];
      }
    ];
    distributedBuilds = true;
    settings = {
      builders-use-substitutes = true;
      trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
      substituters = ["http://max-nixos-workstation-zerotier:8080"];
    };
  };
  services = {
    btrbk = {
      instances = {
        ${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName} = {
          settings = {
            backend_remote = "btrfs-progs-sudo";
            volume = {
              "/nexus" = {
                target = "ssh://max-nixos-workstation-zerotier/Big/backups/${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}";
              };
            };
          };
        };
      };
    };
  };
  systemd = {
    services = {
      "btrbk-${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}" = {
        wants = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" ];
        after = [ "zerotierone.service" "sys-devices-virtual-net-ztmjfp7kiq.device" ];
        serviceConfig = {
          IPAddressAllow = "172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258 fc9c:6b89:eec5:0d88:e258:0000:0000:0001";
          RestrictSUIDSGID = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
          BindReadOnlyPaths = [ "/run/nscd" ];
        };
        unitConfig = {
          OnFailure = "btrbk-retry-${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}.service";
        };
      };
      "btrbk-retry-${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}" =
        let cfg = config.systemd.services."btrbk-${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}";
        in {
          inherit (cfg) wants after confinement restartIfChanged;
          path = lib.mkForce cfg.path;
          serviceConfig = lib.removeAttrs cfg.serviceConfig ["RootDirectory" "InaccessiblePaths" "ReadOnlyPaths" "RuntimeDirectory"] // {
            ExecStart = "${pkgs.btrbk}/bin/btrbk -c /etc/btrbk/${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}.conf resume";
            Restart = "on-failure";
          };
          unitConfig = cfg.unitConfig // {
            OnFailure = [];
          };
        };
      "nixos-upgrade" = {
        after = [ "network-online.target" "zerotierone.service" ];
        description = "NixOS Upgrade";
        serviceConfig = {
          AmbientCapabilities = "CAP_SYS_ADMIN";
          CapabilityBoundingSet = "CAP_SYS_ADMIN";
          NoNewPrivileges = true;
          Type = "oneshot";
          RestartSec = 10;
          Restart = "on-failure";
          User = "nixos-upgrade";
          Group = "nixos-upgrade";
          RemoveIPC = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          SystemCallArchitectures = "native";
          ProtectKernelTunables = true;
          RestrictRealtime = true;
          ProtectHome = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          PrivateTmp = true;
          RestrictNamespaces = true;
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          IPAddressDeny = "any";
          IPAddressAllow = "172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258 fc9c:6b89:eec5:0d88:e258:0000:0000:0001";
          ProtectProc = "invisible";
          MemoryDenyWriteExecute = true;
        };
        path = with pkgs; [
          config.nix.package.out
        ];
        requires = [ "network-online.target" "zerotierone.service" ];
        restartIfChanged = false;
        script = ''
          config="$(${pkgs.curl}/bin/curl "http://max-nixos-workstation-zerotier:8081/${config.networking.hostName}" -f)"
          ${config.nix.package}/bin/nix-env -p /nix/var/nix/profiles/system --set "''${config}"
          "''${config}/bin/switch-to-configuration" boot
        '';
        unitConfig = {
          X-StopOnRemoval = false;
          OnSuccess = "nixos-upgrade-apply.service";
        };
      };
      nixos-upgrade-apply = {
        serviceConfig = {
          ExecStart = "/nix/var/nix/profiles/system/bin/switch-to-configuration switch";
          AmbientCapabilities = "CAP_SYS_ADMIN";
          CapabilityBoundingSet = "CAP_SYS_ADMIN";
          NoNewPrivileges = true;
          Type = "oneshot";
          RestartSec = 10;
          # Restart = "on-failure";
          User = "nixos-upgrade";
          Group = "nixos-upgrade";
          RemoveIPC = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          SystemCallArchitectures = "native";
          ProtectKernelTunables = true;
          RestrictRealtime = true;
          ProtectHome = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          PrivateTmp = true;
          RestrictNamespaces = true;
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          IPAddressDeny = "any";
          ProtectProc = "invisible";
          MemoryDenyWriteExecute = true;
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
      # blkid-cache = {};
      nixos-upgrade = {};
    };
    users = {
      # blkid-cache = {
      #   group = "blkid-cache";
      #   extraGroups = [ "disk" ];
      #   isSystemUser = true;
      # };
      nixos-upgrade = {
        group = "nixos-upgrade";
        extraGroups = [ "disk" ];
        isSystemUser = true;
      };
    };
  };
}
