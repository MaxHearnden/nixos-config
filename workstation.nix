{ config, pkgs, lib, ...}: {
  imports = [./configuration.nix ./hardware-configuration/workstation.nix];
  networking.hostName = "max-nixos-workstation";
  services.xserver.displayManager.gdm.autoSuspend = false;
  services.xserver.displayManager.sessionCommands = "xhost +SI:localuser:max";
  networking.firewall.allowedUDPPorts = [ 25565 ];
  networking.firewall.allowedTCPPorts = [ 25565 ];
  networking.firewall.interfaces.ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 50000 3000 3389 2049 ];
  services.xserver.xrandrHeads = [ "HDMI-3" "HDMI-2" ];
  users.users.max = {
    packages = with pkgs; [
      piper
    ];
  };
  environment.systemPackages = with pkgs; [
    gtk3
  ];

  services.hydra.enable = true;
  services.hydra.hydraURL = "http://172.28.10.244:8080";
  services.hydra.notificationSender = "hydra@example.com";
  services.hydra.listenHost = "172.28.10.244";
  services.hydra.port = 8080;
  services.hydra.extraConfig = ''
    binary_cache_secret_key_file = /etc/nix/storekey
    max_output_size = 8000000000
    Include /var/lib/hydra/gitea_authorisations.conf
  '';
  services.hydra.buildMachinesFiles = ["/machines"];
  services.hydra.useSubstitutes = true;
  systemd.timers.hydra-update-gc-roots.timerConfig.Persistent = true;
  networking.interfaces.enp1s0.ipv4.addresses = [{address = "192.168.2.1"; prefixLength = 24;}];
  networking.interfaces.enp1s0.useDHCP = false;
  services.dhcpd4.enable = true;
  services.dhcpd4.interfaces = [ "enp1s0" ];
  services.dhcpd4.machines = [
    {
      ethernetAddress = "d4:93:90:06:43:76";
      hostName = "max-nixos-laptop";
      ipAddress = "192.168.2.2";
    }
/*    {
      ethernetAddress = "a0:36:9f:c3:d4:c1";
      hostName = "max-nixos-workstation";
      ipAddress = "192.168.2.1";
    }*/
  ];
  services.dhcpd4.extraConfig = ''
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.2.255;
    subnet 192.168.2.0 netmask 255.255.255.0 {
      range 192.168.2.10 192.168.2.250;
    }
  '';
  services.nix-serve.enable = true;
  services.nix-serve.openFirewall = true;
  services.nix-serve.bindAddress = "192.168.2.1";
  services.nix-serve.secretKeyFile = "/etc/nix/storekey";
  services.gitea = {
    enable = true;
    database.type = "postgres";
    settings.service.DISABLE_REGISTRATION = true;
    httpAddress = "172.28.10.244";
    domain = "172.28.10.244";
    rootUrl = "http://172.28.10.244:3000";
    settings.security.DISABLE_GIT_HOOKS=false;
  };
  services.ratbagd.enable = true;
  systemd.services.nixos-upgrade.requires = ["gitea.service"];
  environment.etc."nix/machines" = {
    source = "/machines";
  };

  services.nfs.server = {
    enable = true;
    hostName = "172.28.10.244";
    exports = ''
      /Big/shared max-nixos-*(mp=/Big,rw)
    '';
  };
  services.kerberos_server = {
    enable = true;
    realms."WORKSTATION" = {};
  };

  krb5 = {
    realms = {
      WORKSTATION = {
        master_key_type = "aes256-cts";
        supported_enctypes = "aes256-cts:normal aes128-cts:normal";
      };
    };
  };

}