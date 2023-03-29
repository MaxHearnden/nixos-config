{ config, pkgs, lib, ...}: {
  imports = [./configuration.nix ./hardware-configuration/workstation.nix ./fossil-server.nix];
  networking.hostName = "max-nixos-workstation";
  services.xserver.displayManager.gdm.autoSuspend = false;
  services.xserver.displayManager.sessionCommands = "xhost +SI:localuser:max";
  networking.firewall.allowedUDPPorts = [ 25565 ];
  networking.firewall.allowedTCPPorts = [ 25565 ];
  networking.firewall.interfaces.ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 50000 3000 3389 2049 ];
  networking.firewall.interfaces.ve-teams.allowedTCPPorts = [ 6000 ];
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
  services.hydra.buildMachinesFiles = ["/hydra-machines"];
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
      /Big/shared -mp=/Big,rw,all_squash,anonuid=1000,anongid=100,async max-nixos-* max-guix-*
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

  fileSystems."/home/max/shared" = {
    options = ["x-systemd.after=nfs-server.service"];
  };

  boot.tmpOnTmpfs = true;

  #services.beesd.filesystems.big = {
  #  spec = "UUID=0379ef59-faa8-424c-89a7-cedc93956adc";
  #  hashTableSizeMB = 4096 * 4;
  #};

  #services.sourcehut = {
  #  enable = true;
  #  #git = {
  #  #  enable = true;
  #  #};
  #  #hg = {
  #  #  enable = true;
  #  #};
  #  hub = {
  #    enable = true;
  #  };
  #  meta = {
  #    enable = true;
  #    port = 5051;
  #  };
  #  redis.enable = true;
  #  postgresql.enable = true;
  #  settings = {
  #    "sr.ht" = {
  #      environment = "production";
  #      global-domain = "172.28.10.244";
  #      origin = "http://172.28.10.244";
  #      network-key = "/var/keys/srht-network-key";
  #      service-key = "/var/keys/srht-service-key";
  #    };
  #    "hub.sr.ht" = {
  #      oauth-client-id = "69dff40e2ff892af532c70c3a2f10ecd6f1264caa0981396f499b09c03103d87";
  #      oauth-client-secret = "/var/keys/srht-hub-oauth-secret";
  #      origin = "http://172.28.10.244:5014";
  #    };
  #    "meta.sr.ht" = {
  #      origin = "http://172.28.10.244:5001";
  #    };
  #    mail.pgp-pubkey = "";
  #    mail.pgp-privkey = "";
  #    mail.pgp-key-id = "";
  #    mail.smtp-from = "";
  #    webhooks.private-key = "/var/keys/srht-webhooks-key";
  #  };
  #};
  services.fossil = {
    enable = true;
    port = 3001;
    baseurl = "http://172.28.10.244:3001";
  };

  services.snapper = {
    configs = {
      big = {
        subvolume = "/Big";
      };
    };
  };
  networking = {
    nat = {
      enable = true;
      internalInterfaces = ["ve-+"];
      externalInterface = "eno1";
    };
    networkmanager.unmanaged = ["interface-name:ve-*"];
  };

  systemd.services.nixos-upgrade-all = {
    description = "Builds an upgrade for all my systems";
    restartIfChanged = false;
    unitConfig.X-StopOnRemoval = false;
    serviceConfig.Type = "oneshot";
    path = with pkgs; [
      coreutils
      gnutar
      xz.bin
      gzip
      gitMinimal
      config.nix.package.out
      config.programs.ssh.package
    ];
    script = ''
      config_all="$(nix build git+http://172.28.10.244:3000/zandoodle/nixos-config --no-link --print-out-paths --refresh --recreate-lock-file --no-write-lock-file)"
      nix-env -p /nix/var/nix/profiles/all --set "$config_all"
      config="$(readlink -e $config_all/${config.networking.hostName})"
      nix-env -p /nix/var/nix/profiles/system --set "$config"
      booted="$(${pkgs.coreutils}/bin/readlink /run/booted-system/{initrd,kernel,kernel-modules})"
      built="$(${pkgs.coreutils}/bin/readlink /nix/var/nix/profiles/system/{initrd,kernel,kernel-modules})"
      if [ "''${booted}" = "''${built}" ]; then
        $config/bin/switch-to-configuration switch
      else
        $config/bin/switch-to-configuration boot
      fi
    '';
    startAt = "17:45";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
  };
  systemd.timers.nixos-upgrade-all = {
    timerConfig = {
      Persistent = true;
    };
  };
  nix.distributedBuilds = true;

}
