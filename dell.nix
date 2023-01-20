{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix ./laptop.nix];
  networking.hostName = "max-nixos-dell";
}