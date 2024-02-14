{ lib, pkgs, config, ... }:

{
  imports = [./configuration.nix];
  fileSystems = {
    "/home/max/shared" = {
      device = "172.28.10.244:/Big/shared";
      fsType = "nfs";
      options = [
        "defaults"
        "x-systemd.requires=sys-devices-virtual-net-ztmjfp7kiq.device"
        "x-systemd.requires=zerotierone.service"
        "nofail"
        "noatime"
        "fsc"
        "softreval"
        "async"
      ];
    };
  }
  nix = {
    buildMachines = [
      {
        hostName = "172.28.10.244?remote-program=/run/current-system/sw/bin/ssh-mac-x86";
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
        hostName = "172.28.10.244?remote-program=/run/current-system/sw/bin/ssh-mac";
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
      substituters = ["http://172.28.10.244:8080"];
    };
  };
  services = {
    btrbk = {
      instances = {
        ${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName} = {
          settings = {
            volume = {
              "/nexus" = {
                target = "ssh://172.28.10.244/Big/backups/${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName}";
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
        wants = [ "zerotierone.service" "sys-devices-virtual-new-ztmjfp7kiq.device" ];
        after = [ "zerotierone.service" "sys-devices-virtual-new-ztmjfp7kiq.device" ];
      };
      "nixos-upgrade" = {
        after = [ "network-online.target" "zerotierone.service" ];
        description = "NixOS Upgrade";
        serviceConfig = {
          Type = "oneshot";
          RestartSec = 10;
          Restart = "on-failure";
        };
        path = with pkgs; [
          config.nix.package.out
        ];
        requires = [ "network-online.target" "zerotierone.service" ];
        restartIfChanged = false;
        script = ''
          config="$(${pkgs.curl}/bin/curl "http://172.28.10.244:8081/${config.networking.hostName}" -f)"
          nix-env -p /nix/var/nix/profiles/system --set "''${config}"
          "''${config}/bin/switch-to-configuration" boot
        '';
        unitConfig = {
          X-StopOnRemoval = false;
        };
        wantedBy = [ "default.target" ];
      };
    };
    # timers = {
    #   nixos-upgrade = {
    #     timerConfig = {
    #       Persistent = true;
    #     };
    #   };
    # };
  };
}
