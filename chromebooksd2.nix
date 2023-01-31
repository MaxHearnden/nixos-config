{ config, pkgs, lib, ... }: {
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking.hostName = "max-nixos-chromebooksd2";
  swapDevices = [ {device = "/swapfile"; size = 4096;} ];
  boot.loader.grub.efiInstallAsRemovable = true;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  system.autoUpgrade.enable = lib.mkForce false;
  systemd.services."nixos-upgrade" = {
    description = "NixOS Upgrade";
    restartIfChanged = false;
    unitConfig.X-StopOnRemoval = false;
    serviceConfig.Type = "oneshot";
    path = with pkgs; [
      config.nix.package.out
    ];
    script = ''
      config="$(${config.programs.ssh.package}/bin/ssh 172.28.10.244 nix build git+http://172.28.10.244:3000/zandoodle/nixos-config#nixosConfigurations.${config.networking.hostName}.config.system.build.toplevel --no-link --print-out-paths --refresh --recreate-lock-file --no-write-lock-file)"
      nix-env -p /nix/var/nix/profiles/system --set "$config"
      booted="$(${pkgs.coreutils}/bin/readlink /run/booted-system/{initrd,kernel,kernel-modules})"
      built="$(${pkgs.coreutils}/bin/readlink /nix/var/nix/profiles/system/{initrd,kernel,kernel-modules})"
      if [ "''${booted}" = "''${built}" ]; then
        $config/bin/switch-to-configuration switch
      else
        $config/bin/switch-to-configuration boot
      fi
    '';
    startAt = "17:45";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
  };
  systemd.timers.nixos-upgrade = {
    timerConfig = {
      Persistent = true;
    };
  };
}
