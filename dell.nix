{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix ./laptop.nix ./guix.nix];
  networking = {
    hostName = "max-nixos-dell";
  };
  fileSystems = {
    "/nexus" = {
      device = config.fileSystems."/".device;
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "nosuid" "nodev" "noatime" ];
    };
  };
  #boot.loader.grub.extraConfig = "badram 0x0000000099a09810,0xfffffffffffffff8";
}
