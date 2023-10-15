{pkgs, config, ...}:

{
  imports = [./configuration.nix];
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
  systemd = {
    services = {
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
    timers = {
      nixos-upgrade = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
  };
}
