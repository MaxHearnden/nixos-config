{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix];
  networking.hostName = "max-nixos-dell";
}