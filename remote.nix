{ config, pkgs, lib, ... }: {
  imports = [./configuration.nix];
  nix.settings = {
    trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
    substituters = ["http://172.28.10.244:8080"];
  };
}