{ config, pkgs, lib, ... }: {
  imports = [./remote.nix ./hardware-configuration/dell.nix ./laptop.nix];
  networking.hostName = "max-nixos-dell";
  boot.kernelParams = ["badmem=0x0000000099a09810,0xfffffffffffffff8"]
}