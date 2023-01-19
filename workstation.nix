{ config, pkgs, lib, ...}: {
  imports = [./configuration.nix];
  networking.hostName = "max-nixos-workstation";
  services.xserver.displayManager.gdm.autoSuspend = false;
  services.xserver.displayManager.sessionCommands = "xhost +SI:localuser:max";
  networking.firewall.allowedUDPPorts = [ 25565 ];
  networking.firewall.allowedTCPPorts = [ 25565 ];
  networking.firewall.interfaces.ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 50000 3000 3389 ];
  services.xserver.xrandrHeads = [ "HDMI-3" "HDMI-2" ];
  users.users.max = {
    packages = with pkgs; [
      piper
    ]
  }
}