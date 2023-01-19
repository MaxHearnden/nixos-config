{ config, pkgs, lib, ... }: {
  imports = [./configuration.nix];
  nix.settings = {
    trusted-public-keys = "max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI=";
    substituters = ["http://172.28.10.244:8080"];
  };
  system.autoUpgrade.flake = "git+http://172.28.10.244:3000/zandoodle/nixos-config";
}