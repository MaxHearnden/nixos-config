{ config, pkgs, lib, ... }: {
  imports = [./configuration.nix];
  nix.settings = {
    trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
    substituters = ["http://172.28.10.244:8080"];
  };
  systemd.services."nixos-upgrade" = {
    description = "NixOS Upgrade";
    restartIfChanged = false;
    unitConfig.X-StopOnRemoval = false;
    serviceConfig.Type = "oneshot";
    path = with pkgs; [
      config.nix.package.out
    ];
    script = ''
      config="$(${config.programs.ssh.package}/bin/ssh 172.28.10.244 readlink -e /nix/var/nix/profiles/all/${config.networking.hostName})"
      nix-env -p /nix/var/nix/profiles/system --set "$config"
      booted="$(${pkgs.coreutils}/bin/readlink /run/booted-system/{initrd,kernel,kernel-modules})"
      built="$(${pkgs.coreutils}/bin/readlink /nix/var/nix/profiles/system/{initrd,kernel,kernel-modules})"
      if [ "''${booted}" = "''${built}" ]; then
        $config/bin/switch-to-configuration switch
      else
        $config/bin/switch-to-configuration boot
        ${config.systemd.package}/bin/shutdown -r +1
      fi
    '';
    after = [ "network-online.target" "zerotierone.service" "sys-devices.virtual-net-ztmjfp7kiq.device" ];
    requires = [ "network-online.target" "zerotierone.service" "sys-devices.virtual-net-ztmjfp7kiq.device" ];
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
