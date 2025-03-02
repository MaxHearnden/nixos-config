{ lib, pkgs, config, inputs, ... }:

{
  imports = [./configuration.nix ./hardware-configuration/workstation.nix];
  boot = {
    loader = {
      systemd-boot = {
        enable = true;
      };
    };
    # loader = {
    #   grub = {
    #     default = 3;
    #   };
    # };
    tmp = {
      tmpfsSize = "100%";
    };
  };
  environment = {
    etc =
      lib.listToAttrs (map (file: {
        name = "pcrlock.d/${file}";
        value = {
          source = "${inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.systemd.out}/lib/pcrlock.d/${file}";
        };
      }) [ "400-secureboot-separator.pcrlock.d" "500-separator.pcrlock.d" "700-action-efi-exit-boot-services.pcrlock.d" ]) // 
      lib.listToAttrs (map (file: {
        name = "pcrlock.d/${file}";
        value = {
          source = "/run/booted-system/${file}";
        };
      }) [ "650-systemd-boot.pcrlock" "670-kernel.pcrlock" "705-kernel-cmdline.pcrlock" "710-kernel-cmdline.pcrlock" "720-kernel-initrd.pcrlock" ]) // {
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
      device = config.fileSystems."/Big".device;
      fsType = "btrfs";
      options = config.fileSystems."/Big".options ++ [ "subvol=/shared" ];
      # options = ["x-systemd.requires=nfs-server.service"];
    };
    "/nexus" = {
      device = "/dev/disk/by-uuid/76463411-5c55-4708-bf63-7e3195776b57";
      fsType = "btrfs";
      options = [ "nofail" "defaults" "compress=zstd" "nosuid" "nodev" "noatime" ];
    };
  };
  # krb5 = {
  #   realms = {
  #     WORKSTATION = {
  #       master_key_type = "aes256-cts";
  #       supported_enctypes = "aes256-cts:normal aes128-cts:normal";
  #     };
  #   };
  # };
  nix = {
    distributedBuilds = true;
  };
  networking = {
    firewall = {
      filterForward = true;
      interfaces = {
        ztmjfp7kiq = {
          allowedTCPPorts = [ 8080 8081 3000 2049 25565 ];
          allowedUDPPorts = [ 24454 ];
        };
        tailscale0 = {
          allowedTCPPorts = [ 22 3000 25565 ];
          allowedUDPPorts = [ 24454 ];
        };
        enp2s0 = {
          allowedTCPPorts = [ 5000 53 ];
          allowedUDPPorts = [ 53 69 ];
        };
      };
      extraInputRules = ''
        iifname "enp2s0" udp dport 67 meta nfproto ipv4 accept comment "dnsmasq"
        ip6 daddr { fe80::/64, ff02::1:2, ff02::2 } udp dport 547 iifname "enp2s0" accept comment "dnsmasq"
      '';
    };
    hostName = "max-nixos-workstation";
    # hosts =
    #   lib.listToAttrs (
    #     lib.genList (index:
    #       lib.nameValuePair "192.168.2.1${toString (index + 1)}" [ "nixos-slot${toString (index + 1)}"]
    #     ) 7
    #   );
    # interfaces = {
    #   enp2s0 = {
    #     ipv4 = {
    #       addresses = [
    #         {
    #           address = "192.168.2.1";
    #           prefixLength = 24;
    #         }
    #       ];
    #     };
    #     useDHCP = false;
    #   };
    # };
    localCommands = ''
      # Remove the priority 0 local rule
      ip rule del priority 0 || true
      ip -6 rule del priority 0 || true
    '';
    nat = {
      enable = true;
      externalInterface = "eno1";
      internalInterfaces = [
        "enp2s0"
      ];
    };
    networkmanager = {
      unmanaged = [
        "eno1"
        "enp2s0"
        "enp3s0f0"
        "enp3s0f1"
        "enp3s0f2"
        "enp3s0f3"
      ];
    };
    nftables.tables.zoning = {
      family = "inet";
      content = ''
        chain zoning-prerouting {
          type filter hook prerouting priority raw; policy accept;
          ct zone set meta iifname map {enp3s0f0: 1, enp3s0f1: 2, enp3s0f2: 3, enp3s0f3: 4}
        }

        chain zoning-output {
          type filter hook output priority raw; policy accept;
          ct zone set meta oifname map {enp3s0f0: 1, enp3s0f1: 2, enp3s0f2: 3, enp3s0f3: 4}
        }
      '';
    };
  };
  security = {
    tpm2 = {
      enable = true;
      tctiEnvironment = {
        enable = true;
      };
    };
  };
  services = {
    _3proxy = {
      enable = true;
      services = [
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 3000;
          bindAddress = "max-nixos-workstation-zerotier-6plane";
          extraArguments = "3000 172.28.10.244 3000";
        }
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 3000;
          bindAddress = "max-nixos-workstation-zerotier-rfc4193";
          extraArguments = "3000 172.28.10.244 3000";
        }
        {
          type = "tcppm";
          auth = [ "none" ];
          bindPort = 3000;
          bindAddress = "100.91.224.22";
          extraArguments = "3000 172.28.10.244 3000";
        }
      ];
    };
    btrbk = {
      instances = {
        btrbk = {
          settings = {
            volume = {
              "/nexus" = {
                target = "/Big/backups/workstation";
              };
              "/Big" = {
                subvolume = "shared";
                target = "/nexus/backups/workstation";
              };
            };
          };
        };
      };
      sshAccess = [
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEQQFWFgxHvO9V02h2V7Ylgiou9o745w08xBEddL7HA0 btrbk@max-nixos-pc";
          roles = [
            "receive"
            "delete"
            "source"
          ];
        }
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6GaQD1sg32My+wRYROof6BrFX5XoFDe+f/aggoRUMR btrbk@max-nixos-chromebooksd2";
          roles = [
            "receive"
            "delete"
          ];
        }
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ62a5GL8BnuwriNuk2TamZdnfxAiGTXLQOby88zS3Br btrbk@max-nixos-dell";
          roles = [
            "receive"
            "delete"
          ];
        }
        {
          key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHF5gDfzX8Dya6NMftSbyDgvyrO/lfxxJYjy9RD4kAJX btrbk@max-nixos-laptop";
          roles = [
            "receive"
            "delete"
          ];
        }
      ];
    };
    dbus = {
      packages = [
        (pkgs.writeTextDir "share/dbus-1/system.d/dnsmasq-rootless.conf" ''
          <!DOCTYPE busconfig PUBLIC
           "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
           "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
          <busconfig>
                  <policy user="dnsmasq">
                          <allow own="uk.org.thekelleys.dnsmasq"/>
                          <allow send_destination="uk.org.thekelleys.dnsmasq"/>
                  </policy>
          </busconfig>
        '')
      ];
    };
    dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        bind-interfaces = true;
        conf-file = "${config.services.dnsmasq.package}/share/dnsmasq/trust-anchors.conf";
        dhcp-fqdn = true;
        dhcp-option = [ "option:mtu,9216" ];
        dhcp-range = [ "192.168.2.20,192.168.2.250" "fd80:1234::20,fd80:1234::ffff:ffff:ffff:ffff" ];
        dhcp-rapid-commit = true;
        dnssec = true;
        domain = "home.arpa";
        enable-ra = true;
        interface = [ "enp2s0" ];
        interface-name = "max-nixos-workstation.home.arpa,enp2s0";
        local = ["//" "/home.arpa/"];
        no-hosts = true;
        ra-param = "enp2s0,mtu:enp2s0,0,0";
      };
    };
    gitea = {
      database.type = "postgres";
      enable = true;
      settings = {
        security = {
          DISABLE_GIT_HOOKS = true;
        };
        server = {
          DOMAIN = "max-nixos-workstation-zerotier";
          HTTP_ADDR = "172.28.10.244";
        };
        service = {
          DISABLE_REGISTRATION = true;
        };
      };
    };
    harmonia = {
      enable = true;
      signKeyPaths = ["/etc/nix/storekey"];
      settings = {
        bind = "[::1]:8080";
        priority = 50;
      };
    };
    # hydra = {
    #   buildMachinesFiles = ["/hydra-machines"];
    #   enable = true;
    #   extraConfig = ''
    #     binary_cache_secret_key_file = /etc/nix/storekey
    #     max_output_size = 8000000000
    #     Include /var/lib/hydra/gitea_authorisations.conf
    #   '';
    #   hydraURL = "http://172.28.10.244:8080";
    #   listenHost = "172.28.10.244";
    #   notificationSender = "hydra@example.com";
    #   port = 8080;
    #   useSubstitutes = true;
    # };
    # kea = {
    #   dhcp4 = {
    #     enable = true;
    #     settings = {
    #       interfaces-config = {
    #         interfaces = [
    #           "enp2s0"
    #         ];
    #       };
    #       lease-database = {
    #         name = "/var/lib/kea/dhcp4.leases";
    #         persist = true;
    #         type = "memfile";
    #       };
    #       rebind-timer = 2000;
    #       renew-timer = 1000;
    #       subnet4 = [
    #         {
    #           pools = [
    #             {
    #               pool = "192.168.2.20 - 192.168.2.240";
    #             }
    #           ];
    #           subnet = "192.168.2.0/24";

    #           option-data = [
    #             {
    #               name = "routers";
    #               data = "192.168.2.1";
    #             }
    #           ];
    #           reservations = [
    #             {
    #               hw-address = "48:da:35:60:0e:19";
    #               ip-address = "192.168.2.10";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:18";
    #               hostname = "nixos-slot1";
    #               ip-address = "192.168.2.11";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:12";
    #               hostname = "nixos-slot2";
    #               ip-address = "192.168.2.12";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:16";
    #               hostname = "nixos-slot3";
    #               ip-address = "192.168.2.13";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:14";
    #               hostname = "nixos-slot4";
    #               ip-address = "192.168.2.14";
    #             }
    #             {
    #               hw-address = "56:44:6a:05:fd:90";
    #               hostname = "nixos-slot5";
    #               ip-address = "192.168.2.15";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:0e";
    #               hostname = "nixos-slot6";
    #               ip-address = "192.168.2.16";
    #             }
    #             {
    #               hw-address = "48:da:35:60:0e:28";
    #               hostname = "nixos-slot7";
    #               ip-address = "192.168.2.17";
    #             }
    #             {
    #               hw-address = "36:a9:52:d4:e6:f8";
    #               ip-address = "192.168.2.18";
    #             }
    #           ];
    #         }
    #       ];
    #     };
    #   };
    # };
    minecraft-server = {
      enable = true;
      declarative = true;
      eula = true;
      package = inputs.nix-minecraft.packages.x86_64-linux.fabric-server;
      serverProperties = {
        server-ip = "127.0.0.1";
        server-port = 25564;
      };
    };
    nfs = {
      server = {
        enable = true;
        hostName = "max-nixos-workstation-zerotier-ipv4,max-nixos-workstation-zerotier-6plane,max-nixos-workstation-zerotier-rfc4193,192.168.2.1";
        exports = ''
          /Big/shared -mp=/Big,rw,all_squash,anonuid=1000,anongid=100,async max-nixos-* max-guix-*
          /Big/shared/riscv/star64_root 192.168.2.0/24(rw,no_root_squash,mp=/Big)
          /nix 192.168.2.0/24(ro,no_root_squash)
        '';
      };
    };
    # nix-serve = {
    #   bindAddress = "192.168.2.1";
    #   enable = true;
    #   # openFirewall = true;
    #   secretKeyFile = "/etc/nix/storekey";
    # };
    ratbagd = {
      enable = true;
    };
    resolved = {
      dnssec = "true";
      extraConfig = ''
        Cache=no
      '';
    };
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
        # sessionCommands = "xhost +SI:localuser:max";
      };
    };
  };
  systemd = {
    network = {
      enable = true;
      networks = {
        "10-eno1" = {
          DHCP = "yes";
          matchConfig = {
            Name = "eno1";
          };
          dhcpV4Config = {
            ClientIdentifier = "mac";
            SendHostname = false;
            UseHostname = false;
            UseTimezone = true;
            Use6RD = true;
            UseMTU = true;
            RequestOptions = lib.concatMapStringsSep " " toString (lib.subtractLists [52 53 55] (lib.range 1 254));
          };
          dhcpV6Config = {
            SendHostname = false;
            UseHostname = false;
            UseDomains = "route";
            DUIDType = "link-layer";
          };
          ipv6AcceptRAConfig = {
            UseMTU = true;
          };
          networkConfig = {
            LLDP = true;
            LLMNR = false;
            MulticastDNS = false;
            UseDomains = "route";
            DNSDefaultRoute = true;
          };
        };
        "10-enp2s0" = {
          address = ["192.168.2.1/24" "fd80:1234::1/64"];
          matchConfig = {
            Name = "enp2s0";
          };
          linkConfig = {
            MTUBytes = 9216;
            RequiredForOnline = false;
          };
          domains = [ "home.arpa" ];
          dns = [ "192.168.2.1" "fd80:1234::1" ];
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DNSDefaultRoute = false;
          };
          dhcpPrefixDelegationConfig = {
            UplinkInterface = "eno1";
            SubnetId = 1;
          };
          routingPolicyRules = [
            {
              Family = "both";
              Priority = 2000;
              Table = "local";
            }
          ];
          DHCP = "no";
        };
        "20-vrf-interface" = {
          matchConfig = {
            Name = "vrf-interface-*";
          };
          linkConfig = {
            RequiredForOnline = false;
          };
        };
      } // lib.listToAttrs (
        lib.genList (index:
          lib.nameValuePair "20-enp3s0f${toString index}" {
            DHCP = "yes";
            linkConfig = {
              RequiredForOnline = false;
            };
            matchConfig = {
              Name = "enp3s0f${toString index}";
            };
            networkConfig = {
              DNSDefaultRoute = false;
            };
            ipv6AcceptRAConfig = {
              UseMTU = true;
            };
            dhcpV4Config = {
              Hostname = "max-nixos-workstation-${toString index}";
              UseMTU = true;
              RequestOptions = lib.concatMapStringsSep " " toString (lib.subtractLists [52 53 55] (lib.range 1 254));
            };
            dhcpV6Config = {
              Hostname = "max-nixos-workstation-${toString index}";
            };
            vrf = ["vrf-interface-${toString index}"];
          }) 4);
      netdevs = lib.listToAttrs (
        lib.genList (index:
          lib.nameValuePair "20-vrf-interface-${toString index}" {
            netdevConfig = {
              Kind = "vrf";
              Name = "vrf-interface-${toString index}";
            };
            vrfConfig = {
              Table = 10 + index;
            };
          }) 4);
    };
    services = {
      "3proxy" = {
        serviceConfig = {
          ProtectProc = "invisible";
          ProcSubset = "pid";
          DeviceAllow = "";
          ProtectHome = true;
          PrivateDevices = true;
          IPAddressDeny = "any";
          IPAddressAllow = "100.109.29.126 172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258/88 fc9c:6b89:eec5:0d88:e258:0000:0000:0001/40 192.168.2.1/24";
          ProtectKernelModules = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictNamespaces = true;
          CapabilityBoundingSet = "";
          RestrictRealtime = true;
          PrivateUsers = true;
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          LockPersonality = true;
          RestrictAddressFamilies = "AF_INET AF_INET6";
          ProtectKernelTunables = true;
          ProtectHostname = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          UMask = "0077";
        };
      };
      btrbk-btrbk = {
        serviceConfig = {
          BindPaths = [ "/Big" ];
          PrivateNetwork = true;
          RestrictAddressFamilies = "AF_UNIX";
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
      dnsmasq = {
        preStart = lib.mkForce "";
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          IPAddressAllow = "0.0.0.0 255.255.255.255 fe80::/10 ff02::1 127.0.0.53 fd80:1234::/64 192.168.2.0/24";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateUsers = lib.mkForce false;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = lib.mkForce "strict";
          RemoveIPC = true;
          RestrictNamespaces = true;
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6 AF_NETLINK";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "dnsmasq";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          UMask = "0077";
          User = "dnsmasq";
          BindReadOnlyPaths = [
            "/etc/resolv.conf"
            "/etc/passwd"
            "/run/nscd"
            "/run/dbus/system_bus_socket"
            "/run/systemd/journal/dev-log"
          ];
        };
        confinement = {
          enable = true;
        };
      };
      harmonia = {
        serviceConfig = {
          IPAddressAllow = "::1";
          IPAddressDeny = "any";
          PrivateNetwork = lib.mkForce true;
          RestrictSUIDSGID = true;
          RemoveIPC = true;
        };
        unitConfig = {
          StopWhenUnneeded = true;
        };
        wantedBy = lib.mkForce [];
      };
      harmonia-proxy = {
        after = [ "harmonia.service" "harmonia-proxy.socket" ];
        confinement.enable = true;
        requires = [ "harmonia.service" "harmonia-proxy.socket" ];
        serviceConfig = {
          CapabilityBoundingSet = "";
          DynamicUser = true;
          ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd ::1:8080 --exit-idle-time=5min";
          IPAddressAllow = "::1";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          SystemCallArchitectures = "native";
          RestrictAddressFamilies = "AF_INET6";
          RestrictNamespaces = true;
          RestrictNetworkInterfaces = "ztmjfp7kiq lo";
          RestrictRealtime = true;
          SystemCallFilter = ["@system-service" "~@resources @privileged"];
          UMask = "0077";
        };
        unitConfig.JoinsNamespaceOf = "harmonia.service";
      };
      latest-system = {
        serviceConfig = {
          ExecStart = "${inputs.latest-system.packages.x86_64-linux.default}/bin/latest-system-systemd --protocol activate";
          CapabilityBoundingSet = null;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictAddressFamilies = "none";
          # PrivateDevices = true;
          UMask = "0077";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          BindReadOnlyPaths = "/nix/var/nix/profiles/all/systems";
          SystemCallArchitectures = "native";
          ProtectClock = true;
          ProtectKernelLogs = true;
          PrivateNetwork = true;
          MemoryDenyWriteExecute = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          RestrictRealtime = true;
          RemoveIPC = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          ProtectHome = true;
          IPAddressDeny = "any";
          Restart = "always";
          User = "latest-system";
          Group = "latest-system";
          DynamicUser = true;
          # RootDirectory = "/var/empty";
          # MountAPIVFS = true;
          # RootEphemeral = true;
        };
        confinement = {
          enable = true;
        };
        requires = [ "latest-system.socket" ];
      };
      minecraft-server =
        let mods = pkgs.linkFarmFromDrvs "mods" [
          (pkgs.fetchurl {
            hash = "sha256-2ni2tQjMCO3jaEA1OHXoonZpGqHGVlY/9rzVsijrxVA=";
            url = "https://cdn.modrinth.com/data/9eGKb6K1/versions/pl9FpaYJ/voicechat-fabric-1.21.4-2.5.26.jar";
          })
        ]; in {
        wantedBy = lib.mkForce [ ];
        serviceConfig = {
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          RemoveIPC = true;
          SocketBindAllow = ["ipv4:tcp:25564" "udp:24454"];
          SocketBindDeny = "any";
          StateDirectory = "minecraft";
          StateDirectoryMode = "0700";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          BindReadOnlyPaths = [
            "/run/nscd"
            "/etc/resolv.conf"
            "/run/minecraft-server.stdin"
            "${mods}:/var/lib/minecraft/mods"
          ];
        };
        stopIfChanged = false;
        unitConfig = {
          StopWhenUnneeded = true;
        };
        confinement = {
          enable = true;
          packages = [ pkgs.coreutils mods pkgs.udev ];
        };
        postStart = ''
          for i in $(seq 60); do
            ${pkgs.netcat}/bin/nc -z 127.0.0.1 25564 && exit
            sleep 1
          done
        '';
        environment = {
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.udev ];
        };
      };
      minecraft-server-proxy = {
        requires = [ "minecraft-server-proxy.socket" "minecraft-server.service" ];
        after = [ "minecraft-server-proxy.socket" "minecraft-server.service" ];
        serviceConfig = {
          CapabilityBoundingSet = "";
          DynamicUser = true;
          ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd 127.0.0.1:25564 --exit-idle-time=5min";
          IPAddressAllow = "172.28.0.0/16 100.64.0.0/10 fd7a:115c:a1e0::/48 localhost";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictNetworkInterfaces = "ztmjfp7kiq tailscale0 lo";
          SocketBindDeny = "any";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          BindReadOnlyPaths = "/run/systemd/journal";
          Type = "notify";
          UMask = "0077";
        };
        confinement = {
          enable = true;
        };
      };
      # nix-serve = {
      #   serviceConfig = {
      #     Restart = "always";
      #     CapabilityBoundingSet = null;
      #     NoNewPrivileges = true;
      #     RestrictNamespaces = true;
      #     RestrictAddressFamilies = "AF_INET AF_UNIX";
      #     RootDirectory = "/var/empty";
      #     TemporaryFileSystem = "/";
      #     PrivateTmp = true;
      #     MountAPIVFS = true;
      #     ProtectProc = "invisible";
      #     ProcSubset = "pid";
      #     BindReadOnlyPaths = "/bin/sh /nix/store /nix/var/nix/daemon-socket/socket";
      #     PrivateDevices = true;
      #     PrivateMounts = true;
      #     ProtectSystem = false;
      #     DynamicUser = lib.mkForce false;
      #     RemoveIPC = true;
      #     ProtectClock = true;
      #     ProtectKernelLogs = true;
      #     ProtectControlGroups = true;
      #     ProtectKernelModules = true;
      #     SystemCallArchitectures = "native";
      #     MemoryDenyWriteExecute = true;
      #     RestrictSUIDSGID = true;
      #     ProtectHostname = true;
      #     LockPersonality = true;
      #     ProtectKernelTunables = true;
      #     RestrictRealtime = true;
      #     ProtectHome = true;
      #     PrivateUsers = true;
      #     SystemCallFilter = [ "@system-service" "~@resources" ];
      #     IPAddressAllow = [ "172.28.0.0/16" "192.168.2.0/24" ];
      #     IPAddressDeny = "any";
      #     UMask = "0077";
      #   };
      # };
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
          systemd
          kexec-tools
          inputs.nixos-kexec.packages.x86_64-linux.default
        ];
        restartIfChanged = false;
        script = ''
          config_all="$(nix build git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-config#systems-with-closure --no-link --print-out-paths --refresh --no-write-lock-file --option store daemon)"
          nix-env -p /nix/var/nix/profiles/all --set "''${config_all}"
          systemctl stop latest-system.service
          config="$(readlink -e "''${config_all}/systems/${config.networking.hostName}")"
          nix-env -p /nix/var/nix/profiles/system --set "''${config}"
          booted=$(readlink /run/booted-system/kernel /run/booted-system/kernel-modules)
          current=$(readlink "''${config}/kernel" "''${config}/kernel-modules")
          if [ "''${booted}" != "''${current}" ]
          then
            "''${config}/bin/switch-to-configuration" boot
            nixos-kexec --when "1 hour left"
          else
            if [ "$1" = --specialisation ]
            then
              "''${config}/bin/switch-to-configuration" boot
              "''${config}/specialisation/$2/switch-to-configuration" test
            else
              "''${config}/bin/switch-to-configuration" switch
            fi
          fi
        '';
        startAt = "04:15";
        unitConfig = {
          X-StopOnRemoval = false;
        };
        wants = [ "network-online.target" "gitea.service" ];
      };
      # ntpd = {
      #   serviceConfig = {
      #     # CapabilityBoundingSet = "CAP_SYS_TIME CAP_NET_BIND_SERVICE";
      #     # SystemCallFilter = [ "@system-service @clock" "~@resources" ];
      #     BindPaths = "/var/lib/ntp";
      #     BindReadOnlyPaths = "/etc /var/run/nscd"; #services /etc/localtime /etc/nsswitch.conf /etc/resolv.conf";
      #     UMask = "0755";
      #     DeviceAllow = "/dev/log";
      #     ExecStart =
      #       let cfg = config.services.ntp;
      #           configFile = pkgs.writeText "ntp.conf" ''
      #             driftfile /var/lib/ntp/ntp.drift

      #             restrict default ${toString cfg.restrictDefault}
      #             restrict -6 default ${toString cfg.restrictDefault}
      #             restrict source ${toString cfg.restrictSource}

      #             restrict 127.0.0.1
      #             restrict -6 ::1

      #             ${toString (map (server: "server " + server + " iburst\n") cfg.servers)}

      #             ${cfg.extraConfig}
      #           '';
      #       in
      #     # lib.mkForce "${pkgs.strace}/bin/strace -f ${pkgs.ntp}/bin/ntpd -g -c ${configFile} -u ntp:ntp";
      #     lib.mkForce "${pkgs.coreutils}/bin/cat /proc/mounts";
      #   };
      #   preStart = lib.mkForce "";
      #   confinement = {
      #     enable = true;
      #   };
      # };
      postgresql = {
        serviceConfig =
          let hosts = builtins.toFile "hosts" ''
            127.0.0.1 localhost
            ::1 localhost
          ''; in {
          BindReadOnlyPaths = "${hosts}:/etc/hosts /etc/passwd";
          NoNewPrivileges = true;
          PrivateUsers = lib.mkForce false;
          PrivateNetwork = true;
          Environment = [ "XDG_DATA_DIRS=${config.services.postgresql.package}/share" ];
          IPAddressAllow = "localhost";
          IPAddressDeny = "any";
          RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6";
        };
        confinement = {
          enable = true;
          packages = [ pkgs.gnugrep config.i18n.glibcLocales ];
        };
      };
    };
    sockets = {
      harmonia-proxy = {
        listenStreams = ["172.28.10.244:8080" "[fd80:56c2:e21c:3d4b:c99:93c5:d88:e258]:8080" "[fc9c:6b89:eec5:d88:e258::1]:8080"];
        socketConfig = {
          FreeBind = true;
          IPAddressAllow = "172.28.0.0/16 fd80:56c2:e21c:3d4b:c99:9300::/88 fc9c:6b89:ee00::/40";
          IPAddressDeny = "any";
        };
        wantedBy = [ "sockets.target" ];
      };
      latest-system = {
        listenStreams = ["172.28.10.244:8081" "[fd80:56c2:e21c:3d4b:c99:93c5:d88:e258]:8081" "[fc9c:6b89:eec5:d88:e258::1]:8081"];
        socketConfig = {
          FreeBind = true;
          IPAddressAllow = "172.28.0.0/16 fd80:56c2:e21c:3d4b:c99:9300::/88 fc9c:6b89:ee00::/40";
          IPAddressDeny = "any";
        };
        wantedBy = [ "multi-user.target" ];
      };
      minecraft-server = {
        bindsTo = lib.mkForce [];
        partOf = [ "minecraft-server.target" ];
        wantedBy = [ "minecraft-server.target" ];
      };
      minecraft-server-proxy = {
        listenStreams = [ "172.28.10.244:25565" "127.0.0.1:25565" "100.91.224.22:25565" "[fd7a:115c:a1e0:ab12:4843:cd96:625b:e016]:25565" ];
        partOf = [ "minecraft-server.target" ];
        socketConfig = {
          FreeBind = true;
        };
        wantedBy = [ "minecraft-server.target" ];
      };
    };
    targets = {
      minecraft-server = {
        # Only starts the sockets
        wantedBy = [ "sockets.target" ];
      };
    };
    timers = {
      nixos-upgrade-all = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
    tmpfiles = {
      rules = [
        "d /Big/snapshots/btrbk - btrbk btrbk"
        "v /Big/backups 700 btrbk btrbk"
        "d /Big/backups/pc"
        "d /Big/backups/dell"
        "d /Big/backups/chromebooksd2"
        "d /Big/backups/laptop"
        "d /Big/backups/workstation - btrbk btrbk"
        "v /nexus/backups 700 btrbk btrbk"
        "d /nexus/backups/workstation - btrbk btrbk"
        "a /Big/shared - - - - u:btrbk:rx,g::-,m::rx"
      ];
    };
  };
  users = {
    groups = {
      # nix-serve = {};
    };
    users = {
      btrbk = {
        packages = with pkgs; [
          zstd
        ];
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
      # nix-serve = {
      #   isSystemUser = true;
      #   group = "nix-serve";
      # };
    };
  };
}
