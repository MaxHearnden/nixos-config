{ lib, pkgs, config, inputs, ... }:

{
  imports = [
    ./configuration.nix
    ./hardware-configuration/workstation.nix
    ./zone.nix
  ];
  boot = {
    loader = {
      systemd-boot = {
        enable = true;
      };
    };
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
      }) [ "650-systemd-boot.pcrlock" "670-kernel.pcrlock"
      "705-kernel-cmdline.pcrlock" "710-kernel-cmdline.pcrlock"
      "720-kernel-initrd.pcrlock" ])
      // {
        "bind/named.conf".source = config.services.bind.configFile;
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
    };
    "/nexus" = {
      device = "/dev/disk/by-uuid/76463411-5c55-4708-bf63-7e3195776b57";
      fsType = "btrfs";
      options = [ "nofail" "defaults" "compress=zstd" "nosuid" "nodev" "noatime" ];
    };
  };
  nix.settings.keep-outputs = true;
  networking = {
    firewall = {
      filterForward = true;
      interfaces = {
        ztmjfp7kiq = {
          allowedTCPPorts = [ 53 8080 8081 3000 2049 25565 ];
          allowedUDPPorts = [ 53 24454 ];
        };
        tailscale0 = {
          allowedTCPPorts = [ 22 53 3000 25565 ];
          allowedUDPPorts = [ 53 24454 ];
        };
        enp2s0 = {
          allowedTCPPorts = [ 5000 53 ];
          allowedUDPPorts = [ 53 69 ];
        };
        "sl*" = {
          allowedTCPPorts = [ 5000 53 ];
          allowedUDPPorts = [ 53 69 ];
        };
      };
      extraInputRules = ''
        iifname {"enp2s0", "sl*"} udp dport 67 meta nfproto ipv4 accept comment "dnsmasq"
        ip6 daddr { fe80::/64, ff02::1:2, ff02::2 } udp dport 547 iifname "enp2s0" accept comment "dnsmasq"
      '';
    };
    hostName = "max-nixos-workstation";
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
        "sl*"
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
        "sl*"
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
    bind = {
      enable = true;
      extraOptions = ''
        listen-on port 54 { 127.0.0.1; };
        listen-on-v6 port 54 { ::1; };
        managed-keys-directory "/var/lib/named/keys";
        key-directory "/var/lib/named/keys";
      '';
      listenOn = [ "172.28.10.244" "100.91.224.22" ];
      listenOnIpv6 = [
        "fc9c:6b89:eec5:0d88:e258:0000:0000:0001"
        "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258"
        "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016"
      ];
      zones = {
        "home.arpa" = {
          file = builtins.toFile "home.arpa" ''
            @ SOA localhost. nobody.invalid. 1 3600 1200 604800 10800
            @ NS localhost.
            max NS dns.max
            dns.max A 172.28.10.244
            dns.max AAAA fc9c:6b89:eec5:0d88:e258:0000:0000:0001
            dns.max AAAA fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258
          '';
          master = true;
          slaves = [ "any" ];
        };
        "maxh" = {
          file = builtins.toFile "zonefile" ''
            @ SOA localhost. nobody.invalid. 1 3600 1200 604800 10800
            @ NS localhost.
            @ DNAME tailscale.max.home.arpa.
          '';
          master = true;
          slaves = [ "any" ];
        };
        "max.home.arpa" = {
          file = "/run/zone/home/zonefile";
          master = true;
          slaves = [ "any" ];
        };
      };
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
        bind-dynamic = true;
        conf-file = "${config.services.dnsmasq.package}/share/dnsmasq/trust-anchors.conf";
        dhcp-fqdn = true;
        dhcp-option = [ "option:mtu,9216" ];
        dhcp-range = [ "192.168.2.20,192.168.2.250" "192.168.3.20,192.168.3.250" "fd80:1234::20,fd80:1234::ffff:ffff:ffff:ffff" ];
        dhcp-rapid-commit = true;
        dnssec = true;
        domain = "home.arpa";
        enable-ra = true;
        interface = [ "enp2s0" "sl*" ];
        interface-name = "max-nixos-workstation.home.arpa,enp2s0";
        local = ["//" "/home.arpa/"];
        server = ["/max.home.arpa/#"];
        trust-anchor = [
          "max.home.arpa.,6286,16,2,E5D985578B9746BFE1C6FF47E87E27F9BE9942BF947C7AE18C448C86C303DB0E"
          "max.home.arpa.,5629,14,4,663B18A6E58159EA67190937115450B87C60222A4F8D13395ACF3B091CF6155E4BE365D636452E9427C7818866BE9D65"
        ];
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
    openssh.startWhenNeeded = true;
    ratbagd = {
      enable = true;
    };
    resolved = {
      dnssec = "true";
      extraConfig = ''
        DNS=127.0.0.52%lo
        Domains=max.home.arpa
        Cache=no
      '';
    };
    unbound = {
      resolveLocalQueries = false;
      settings = {
        server = {
          do-not-query-localhost = false;
          interface = ["127.0.0.52"];
          trust-anchor-file = map (key: "/var/lib/zone/home/${key}/.ds")
          (lib.attrNames config.services.zones.home.ksks);
          use-systemd = true;
        };
        stub-zone = [
          {
            name = "home.arpa";
            stub-addr = "127.0.0.1@54";
          }
          {
            name = "max.home.arpa";
            stub-addr = "127.0.0.1@54";
          }
        ];
      };
    };
    xserver = {
      displayManager = {
        gdm = {
          autoSuspend = false;
        };
      };
    };
    zones.home = {
      zoneLifetime = 60 * 60 * 24 * 3;
      zskAlgorithms = [ "ed448" "ecdsap384sha384" ];
      domain = "max.home.arpa";
      ksks = {
        max-1 = "ed448";
        max-2 = "ecdsap384sha384";
      };
      signzoneArgs = "-u -b -z sha512";
      zone = ''
        max.home.arpa SOA dns nobody.invalid. 0 7200 60 ${toString (2 * 24 *
        60 * 60)} 1800
        @ NS workstation.zerotier
        cache CNAME workstation
        cache.tailscale CNAME workstation.tailscale
        cache.zerotier CNAME workstation.zerotier
        dns CNAME workstation
        dns.tailscale CNAME workstation.tailscale
        dns.zerotier CNAME workstation.zerotier
        gitea CNAME workstation
        minecraft CNAME minecraft.tailscale
        minecraft.zerotier CNAME workstation.zerotier
        minecraft.tailscale CNAME workstation.tailscale
        chromebook CNAME chromebook.zerotier
        chromebook.zerotier A 172.28.156.146
        chromebook.zerotier AAAA fc9c:6b89:ee1a:7a70:b542::1
        chromebook.zerotier AAAA fd80:56c2:e21c:3d4b:c99:931a:7a70:b542
        workstation CNAME workstation.zerotier
        workstation.zerotier A 172.28.10.244
        workstation.zerotier AAAA fd80:56c2:e21c:3d4b:c99:93c5:d88:e258
        workstation.zerotier AAAA fc9c:6b89:eec5:d88:e258::1
        workstation.tailscale A 100.91.224.22
        workstation.tailscale AAAA fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
        pc CNAME pc.zerotier
        pc.zerotier A 172.28.13.156
        pc.zerotier AAAA fd80:56c2:e21c:3d4b:c99:93d9:c2b9:c567
        pc.zerotier AAAA fc9c:6b89:eed9:c2b9:c567::1
      '';
      zoneFiles = [ "/nix/var/nix/profiles/all/zonefile" ];
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
          macvlan = [ "eno1-web" ];
          dhcpV4Config = {
            ClientIdentifier = "mac";
            SendHostname = false;
            UseHostname = false;
            UseMTU = true;
          };
          dhcpV6Config = {
            SendHostname = false;
            UseHostname = false;
            DUIDType = "link-layer";
          };
          ipv6AcceptRAConfig = {
            UseMTU = true;
          };
          networkConfig = {
            LLDP = true;
            LLMNR = false;
            MulticastDNS = false;
            UseDomains = false;
            DNSDefaultRoute = false;
          };
        };
        "10-eno1-web" = {
          matchConfig = {
            Name = "eno1-web";
          };
          DHCP = "yes";
          dhcpV4Config = {
            ClientIdentifier = "mac";
            Hostname = "max-webserver";
            UseHostname = false;
            UseMTU = true;
          };
          dhcpV6Config = {
            SendHostname = false;
            UseHostname = false;
            DUIDType = "link-layer";
          };
          ipv6AcceptRAConfig = {
            UseMTU = true;
          };
          networkConfig = {
            LLDP = true;
            LLMNR = false;
            MulticastDNS = false;
            UseDomains = false;
            DNSDefaultRoute = false;
          };
          vrf = [ "vrf-web" ];
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
        "10-sl" = {
          address = ["192.168.3.1/24"];
          matchConfig = {
            Name = "sl*";
          };
          linkConfig = {
            MTUBytes = 9216;
            RequiredForOnline = false;
          };
          domains = [ "home.arpa" ];
          dns = [ "192.168.3.1" ];
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DNSDefaultRoute = false;
          };
          DHCP = "no";
        };
        "10-vrf-web" = {
          matchConfig = {
            Name = "vrf-web";
          };
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
          }) 4)
        // {
          "10-eno1-web" = {
            netdevConfig = {
              Kind = "macvlan";
              Name = "eno1-web";
            };
            macvlanConfig = {
              Mode = "bridge";
            };
          };
          "10-vrf-web" = {
            netdevConfig = {
              Kind = "vrf";
              Name = "vrf-web";
            };
            vrfConfig = {
              Table = 20;
            };
          };
        };
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
      bind = {
        confinement.enable = true;
        preStart = lib.mkForce ''
          if ! [ -f "/etc/bind/rndc.key" ]; then
            ${config.services.bind.package.out}/bin/rndc-confgen -c \
              /etc/bind/rndc.key -a -A hmac-sha256 2>/dev/null
          fi
        '';
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE";
          BindReadOnlyPaths = [
            "/run/systemd/journal/dev-log"
            "/run/zone/home"
          ];
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
          ConfigurationDirectory = "bind";
          ExecStart = lib.mkForce "${config.services.bind.package.out}/bin/named -c ${config.services.bind.configFile}";
          Group = "named";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateUsers = lib.mkForce [];
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = [
            "named/keys"
          ];
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          User = "named";
        };
        wants = [ "zone-home.service" ];
        after = [ "zone-home.service" ];
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
      get-IP-address = {
        confinement = {
          enable = true;
        };
        serviceConfig = {
          CapabilityBoundingSet = "";
          Group = "ddns";
          IPAddressAllow = "192.168.1.1";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_INET";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RuntimeDirectory = "ddns";
          StateDirectory = "ddns";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          User = "ddns";
        };
        script = ''
          ${lib.getExe pkgs.curl} -o /run/ddns/login.lp -v \
            http://192.168.1.1/login.lp?getSessionStatus=true
          ${lib.getExe pkgs.jq} -r .wanIPAddress /run/ddns/login.lp \
            >/run/ddns/IPv4-address
          lines=$(${lib.getExe' pkgs.coreutils "wc"} -l --total=only \
            /run/ddns/IPv4-address)
          if [ "''${lines}" = 1 ]; then
            mv -f /run/ddns/IPv4-address /var/lib/ddns/IPv4-address
            printf "@ A " | ${lib.getExe' pkgs.coreutils "cat"} - \
              /var/lib/ddns/IPv4-address >/var/lib/ddns/zonefile
          else
            echo "WARNING: INVALID IPV4 ADDRESS" >&2
            exit 1
          fi
        '';
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
        };
        confinement = {
          enable = true;
        };
        requires = [ "latest-system.socket" ];
      };
      minecraft-server =
        let mods = pkgs.linkFarmFromDrvs "mods" [
          (pkgs.fetchurl {
            hash = "sha256-fn5gtJEA6eA2t3YpMT+/mGwuLtLLOf2OWLNS7QI0rzY=";
            url =
              "https://cdn.modrinth.com/data/9eGKb6K1/versions/suJqF5xU/voicechat-fabric-1.21.5-2.5.30.jar";
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
      nixos-upgrade-all = {
        after = [ "network-online.target" "gitea.service" ];
        description = "NixOS upgrade all";
        onSuccess = [ "latest-system-restart.target" "zone-home.target" ];
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
          config_all="$(nix build git+http://max-nixos-workstation-zerotier:3000/zandoodle/nixos-config#systems-with-zone --no-link --print-out-paths --refresh --no-write-lock-file --option store daemon)"
          nix-env -p /nix/var/nix/profiles/all --set "''${config_all}"
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
      slattach = {
        confinement = {
          enable = true;
        };
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_ADMIN";
          BindPaths = "/dev/ttyS0";
          CapabilityBoundingSet = "CAP_NET_ADMIN";
          DeviceAllow = "/dev/ttyS0";
          DynamicUser = true;
          ExecStart = "${lib.getBin pkgs.nettools}/bin/slattach -L -s 115200 /dev/ttyS0";
          Group = "dialout";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          PrivateUsers = lib.mkForce false;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHostname = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          RestrictAddressFamilies = "none";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = ["@system-service" "~@privileged @resources"];
          Type = "exec";
          UMask = "077";
          User = "slattach";
        };
        wantedBy = [ "multi-user.target" ];
      };
      systemd-resolved.restartTriggers = [
        config.environment.etc."dnssec-trust-anchors.d/home.positive".source
      ];
      bind-reload = {
        after = [ "bind.service" "zone-home.service" ];
        confinement = {
          enable = true;
        };
        serviceConfig = {
          CapabilityBoundingSet = "";
          ConfigurationDirectory = "bind";
          ExecStart = "${lib.getExe' pkgs.bind "rndc"} reload max.home.arpa";
          Group = "named";
          IPAddressDeny = "any";
          IPAddressAllow = "localhost";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_INET AF_NETLINK";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RuntimeDirectoryPreserve = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          UMask = "077";
          User = "named";
        };
        wantedBy = [ "zone-home.service" ];
        wants = [ "bind.service" ];
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
      sshd.enable = false;
      "sshd@lo" = {
        description = "SSH Sockets";
        socketConfig = {
          Accept = true;
          ListenStream = 22;
          TriggerLimitIntervalSec = 0;
          BindToDevice = "lo";
        };
        wantedBy = [ "sockets.target" ];
      };
      "sshd@tailscale" = {
        description = "SSH Sockets";
        socketConfig = {
          Accept = true;
          ListenStream = 22;
          TriggerLimitIntervalSec = 0;
          BindToDevice = "tailscale0";
        };
        wantedBy = [ "sys-subsystem-net-devices-tailscale0.device" ];
      };
      "sshd@zerotier" = {
        description = "SSH Sockets";
        socketConfig = {
          Accept = true;
          ListenStream = 22;
          TriggerLimitIntervalSec = 0;
          BindToDevice = "ztmjfp7kiq";
        };
        wantedBy = [ "sys-subsystem-net-devices-ztmjfp7kiq.device" ];
      };
    };
    targets = {
      latest-system-restart = {
        description = "Restart latest-system service";
        conflicts = [ "latest-system.service" ];
        unitConfig.StopWhenUnneeded = true;
      };
      nfs-client = {
        enable = false;
      };
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
      zone-home = {
        timerConfig = {
          OnCalendar = "daily UTC";
          Unit = "zone-home.target";
        };
        wantedBy = [ "timers.target" ];
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
    users = {
      ddns = {
        isSystemUser = true;
        group = "ddns";
      };
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
    };
    groups.ddns = {};
  };
}
