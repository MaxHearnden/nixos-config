{ lib, pkgs, ... }:

{
  boot = {
    loader = {
      grub = {
        efiInstallAsRemovable = true;
      };
      efi = {
        canTouchEfiVariables = lib.mkForce false;
      };
    };
  };
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking = {
    hostName = "max-nixos-chromebooksd2";
  };
  services = {
    btrbk = {
      extraPackages = with pkgs; [
        zstd
      ];
      instances = {
        pc = {
          settings = {
            target_preserve_min = "no";
            target_preserve = "2w 6m";
            ssh_user = "btrbk";
            send_compressed_data = "yes";
            stream_buffer = "%25";
            stream_compress = "zstd";
            snapshot_preserve = "14d 2w 3m";
            snapshot_preserve_min = "2d";
            snapshot_dir = "snapshots/btrbk";
            transaction_syslog = "user";
            target = "ssh://172.28.10.244/Big/backups/chromebooksd2";
            volume = {
              "/nexus" = {
                subvolume = "@NixOS";
              };
            };
          };
        };
      };
    };
  };
  swapDevices = [
    {
      device = "/swapfile";
    }
  ];
}
