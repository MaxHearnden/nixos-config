{ config, pkgs, lib, ... }: {
  imports = [./configuration.nix];
  nix.settings = {
    trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
    substituters = ["http://172.28.10.244:8080"];
  };
  nix.buildMachines = [
    {
      systems = [ "x86_64-darwin" ];
      supportedFeatures = [
        "big-parallel"
        "benchmark"
      ];
      sshUser = "max";
      protocol = "ssh-ng";
      hostName = "172.28.10.244?remote-program=/nix/var/nix/profiles/system/sw/bin/ssh-mac-x86";
      maxJobs = 4;
    }
    {
      systems = [ "aarch64-darwin" ];
      supportedFeatures = [
        "big-parallel"
        "benchmark"
      ];
      sshUser = "max";
      protocol = "ssh-ng";
      hostName = "172.28.10.244?remote-program=/nix/var/nix/profiles/system/sw/bin/ssh-mac";
      maxJobs = 8;
    }
  ];
  nix.distributedBuilds = true;
  nix.settings.builders-use-substitutes = true;
  systemd.services."nixos-upgrade" = {
    description = "NixOS Upgrade";
    restartIfChanged = false;
    unitConfig.X-StopOnRemoval = false;
    serviceConfig = {
      Type = "oneshot";
      RestartSec = 10;
      Restart = "on-failure";
    };
    path = with pkgs; [
      config.nix.package.out
    ];
    script = ''
      config="$(${config.programs.ssh.package}/bin/ssh 172.28.10.244 readlink -e /nix/var/nix/profiles/all/${config.networking.hostName})"
      nix-env -p /nix/var/nix/profiles/system --set "$config"
      # booted="$(${pkgs.coreutils}/bin/readlink /run/booted-system/{initrd,kernel,kernel-modules})"
      # built="$(${pkgs.coreutils}/bin/readlink /nix/var/nix/profiles/system/{initrd,kernel,kernel-modules})"
      # if [ "''${booted}" = "''${built}" ]; then
      #   $config/bin/switch-to-configuration switch
      # else
      $config/bin/switch-to-configuration boot
      # fi
    '';
    after = [ "network-online.target" "zerotierone.service" ];
    requires = [ "network-online.target" "zerotierone.service" ];
    wantedBy = [ "default.target" ];
  };
  systemd.timers.nixos-upgrade = {
    timerConfig = {
      Persistent = true;
    };
  };
 # nix.buildMachines = [
  #   {
  #     systems = [ "riscv64-linux" "mips-linux" "mipsel-linux" "mips64-linux" "mips64el-linux" "aarch64-linux" "riscv32-linux" "x86_64-linux" "i686-linux" ];
  #     sshUser = "root";
  #     hostName = "172.28.10.244";
  #     maxJobs = 4;
  #     supportedFeatures = [ "kvm"
  #       "big-parallel"
  #       "benchmark"
  #       "nixos-test"
  #     ];
  #   }
  # ];
  # nix.distributedBuilds = true;

}
