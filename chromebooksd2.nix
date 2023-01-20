{ config, pkgs, lib, ... }: {
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking.hostName = "max-nixos-chromebooksd2";
}
