{ config, pkgs, lib, ... }: {
  imports = [ ./remote.nix ];
  networking.hostName = "max-nixos-chromebooksd2";
}
