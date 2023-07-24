{ pkgs, config, inputs, ... }:

{
  imports = [./configuration.nix ./hardware-configuration/workstation.nix];
  boot = {
    loader = {
      grub = {
        default = 3;
      };
    };
    tmp = {
      tmpfsSize = "100%";
    };
  };
  environment = {
    etc = {
      "nix/machines" = {
        source = "/machines";
      };
    };
    systemPackages = with pkgs; [
      gtk3
      (
        pkgs.writeShellScriptBin "ssh-mac"
        ''
          exec ssh -a -x -C max@172.28.31.224 /nix/var/nix/profiles/default/bin/nix-daemon "$@"
        ''
      )
      (
        pkgs.writeShellScriptBin "ssh-mac-x86"
        ''
          exec ssh -a -x -C max@172.28.226.152 /nix/var/nix/profiles/default/bin/nix-daemon "$@"
        ''
      )
    ];
  };
  fileSystems = {
    "/home/max/shared" = {
      options = ["x-systemd.after=nfs-server.service"];
    };
  };
  krb5 = {
    realms = {
      WORKSTATION = {
        master_key_type = "aes256-cts";
        supported_enctypes = "aes256-cts:normal aes128-cts:normal";
      };
    };
  };
  nix = {
    distributedBuilds = true;
  };
  networking = {
    firewall = {
      interfaces = {
        ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 3000 2049 ];
      };
    };
    hostName = "max-nixos-workstation";
    interfaces = {
      enp1s0 = {
        # ipv4 = {
        #   addresses = [
        #     {
        #       address = "192.168.2.1";
        #       prefixLength = 24;
        #     }
        #   ];
        # };
        # useDHCP = false;
      };
    };
  };
  services = {
    gitea = {
      database.type = "postgres";
      enable = true;
      settings = {
        security = {
          DISABLE_GIT_HOOKS = true;
        };
        server = {
          DOMAIN = "172.28.10.244";
          HTTP_ADDR = "172.28.10.244";
        };
        service = {
          DISABLE_REGISTRATION = true;
        };
      };
    };
    hydra = {
      buildMachinesFiles = ["/hydra-machines"];
      enable = true;
      extraConfig = ''
        binary_cache_secret_key_file = /etc/nix/storekey
        max_output_size = 8000000000
        Include /var/lib/hydra/gitea_authorisations.conf
      '';
      hydraURL = "http://172.28.10.244:8080";
      listenHost = "172.28.10.244";
      notificationSender = "hydra@example.com";
      port = 8080;
      useSubstitutes = true;
    };
    kerberos_server = {
      enable = true;
      realms."WORKSTATION" = {};
    };
    nfs = {
      server = {
        enable = true;
        hostName = "172.28.10.244,192.168.2.1";
        exports = ''
          /Big/shared -mp=/Big,rw,all_squash,anonuid=1000,anongid=100,async max-nixos-* max-guix-*
          /Big/shared/riscv/star64_root 192.168.2.0/24(rw,no_root_squash,mp=/Big)
          /nix 192.168.2.0/24(ro,no_root_squash)
        '';
      };
    };
    nix-serve = {
      bindAddress = "192.168.2.1";
      enable = true;
      openFirewall = true;
      secretKeyFile = "/etc/nix/storekey";
    };
    ratbagd = {
      enable = true;
    };
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
        sessionCommands = "xhost +SI:localuser:max";
      };
      xrandrHeads = [ "HDMI-3" "HDMI-2" ];
    };
  };
  systemd = {
    network = {
      enable = true;
      networks = {
        "10-enp1s0" = {
          address = ["192.168.2.1/24"];
          dhcpServerConfig = {
            EmitDNS = false;
            PoolOffset = 10;
            PoolSize = 240;
          };
          dhcpServerStaticLeases = [
            {
              dhcpServerStaticLeaseConfig = {
                MACAddress = "d4:93:90:06:43:76";
                Address = "192.168.2.2";
              };
            }
          ];
          matchConfig = {
            Name = "enp1s0";
          };
          networkConfig = {
            DHCPServer = true;
          };
        };
      };
    };
    services = {
      latest-system = {
        script = ''
          exec ${inputs.latest-system.packages.x86_64-linux.default}/bin/latest-system
        '';
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        requires = [ "network-online.target" ];
        serviceConfig = {
          Restart = "always";
          User = "latest-system";
          Group = "latest-system";
          DynamicUser = true;
        };
      };
      nixos-upgrade-all = {
        after = [ "network-online.target" "gitea.service" ];
        description = "NixOS upgrade all";
        path = with pkgs; [
          coreutils
          gnutar
          xz.bin
          gzip
          gitMinimal
          config.nix.package.out
          config.programs.ssh.package
        ];
        restartIfChanged = false;
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
        unitConfig = {
          X-StopOnRemoval = false;
        };
        wants = [ "network-online.target" "gitea.service" ];
      };
    };
    timers = {
      nixos-upgrade-all = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
  };
  users = {
    users = {
      max = {
        packages = with pkgs; [
          piper
        ];
      };
    };
  };
}
