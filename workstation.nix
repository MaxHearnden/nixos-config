{ lib, pkgs, config, inputs, ... }:

{
  imports = [
    ./configuration.nix
    ./hardware-configuration/workstation.nix
  ];
  boot = {
    kernel.sysctl."net.ipv6.conf.all.forwarding" = 1;
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
        "knot/max.home.arpa.zone".text = ''
          @ SOA workstation.zandoodle.me.uk. nobody.invalid. 0 7200 60 ${toString (2 * 24 *
          60 * 60)} 1800
          @ NS workstation.zandoodle.me.uk.
          cache CNAME workstation
          cache.tailscale CNAME workstation.tailscale
          cache.zerotier CNAME workstation.zerotier
          dns CNAME workstation.tailscale
          dns.tailscale CNAME workstation.tailscale
          dns.zerotier CNAME workstation.zerotier
          minecraft CNAME minecraft.tailscale
          minecraft.zerotier CNAME workstation.zerotier
          minecraft.tailscale CNAME workstation.tailscale
          chromebook CNAME chromebook.tailscale
          chromebook.zerotier A 172.28.156.146
          chromebook.zerotier AAAA fc9c:6b89:ee1a:7a70:b542::1
          chromebook.zerotier AAAA fd80:56c2:e21c:3d4b:c99:931a:7a70:b542
          chromebook.tailscale A 100.69.85.70
          chromebook.tailscale AAAA fd7a:115c:a1e0::d401:5546
          workstation CNAME workstation.tailscale
          workstation.zerotier A 172.28.10.244
          workstation.zerotier AAAA fd80:56c2:e21c:3d4b:c99:93c5:d88:e258
          workstation.zerotier AAAA fc9c:6b89:eec5:d88:e258::1
          workstation.tailscale A 100.91.224.22
          workstation.tailscale AAAA fd7a:115c:a1e0:ab12:4843:cd96:625b:e016
          pc CNAME pc.tailscale
          pc.zerotier A 172.28.13.156
          pc.zerotier AAAA fd80:56c2:e21c:3d4b:c99:93d9:c2b9:c567
          pc.zerotier AAAA fc9c:6b89:eed9:c2b9:c567::1
          pc.tailscale A 100.95.236.105
          pc.tailscale AAAA fd7a:115c:a1e0::d2df:ec69
          $INCLUDE /nix/var/nix/profiles/all/zonefile
        '';
        "resolv.conf".text = ''
          nameserver 127.0.0.53
          options edns0 trust-ad
          search max.home.arpa home.arpa
        '';
        "tayga/tayga.conf".text = ''
          tun-device tayga
          ipv4-addr 192.0.0.2
          ipv6-addr fd64::1
          map 192.0.0.1 fd64::2
          prefix fc9c:6b89:eed9:c2b9:c567:1::/96
        '';
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
          allowedTCPPorts = [ 53 80 443 8080 8081 3000 2049 25565 ];
          allowedUDPPorts = [ 53 443 24454 ];
        };
        tailscale0 = {
          allowedTCPPorts = [ 22 53 80 88 443 464 749 2049 3000 25565 ];
          allowedUDPPorts = [ 53 88 443 464 2049 24454 ];
        };
        enp2s0 = {
          allowedTCPPorts = [ 5000 53 80 443 ];
          allowedUDPPorts = [ 53 69 443 ];
        };
      };
      extraForwardRules = ''
        iifname tayga oifname ztmjfp7kiq accept
      '';
      extraInputRules = ''
        iifname "enp2s0" udp dport 67 meta nfproto ipv4 accept comment "dnsmasq"
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
      externalInterface = "tayga";
      internalInterfaces = [
        "enp2s0"
      ];
    };
    networkmanager = {
      unmanaged = [
        "eno1"
        "enp2s0"
        "ens4f0"
        "ens4f1"
        "ens4f2"
        "ens4f3"
      ];
    };
    nftables.tables = {
      zoning = {
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
      tayga-nat66 = {
        family = "ip6";
        content = ''
          chain tayga-nat {
            type nat hook postrouting priority srcnat; policy accept;
            iifname tayga oifname ztmjfp7kiq masquerade
          }
        '';
      };
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
    caddy = {
      enable = true;
      globalConfig = ''
        acme_ca "https://acme-v02.api.letsencrypt.org/directory"
        admin "unix//run/caddy/caddy.sock"
        dns rfc2136 {
          key_name {file./run/credentials/caddy.service/tsig-id}
          key_alg {file./run/credentials/caddy.service/tsig-algorithm}
          key {file./run/credentials/caddy.service/tsig-secret}
          server [::1]:54
        }
        key_type p384
        preferred_chains smallest
      '';
      package = pkgs.caddy.withPlugins {
        plugins = [ "github.com/caddy-dns/rfc2136@v1.0.0" ];
        hash = "sha256-f/grl1eTVWqem0us5ucxHizChqUfexymh67OD0PDwn8=";
      };
      virtualHosts = {
        "*.workstation.zandoodle.me.uk".extraConfig = ''
          tls {
            issuer acme {
              dns
              profile shortlived
              resolvers fd7a:115c:a1e0::1a01:5208
            }
          }

          header {
            Cross-Origin-Resource-Policy same-origin
            Referrer-Policy no-referrer
            Strict-Transport-Security "max-age=31536000; includeSubdomains; preload"
            X-Content-Type-Options nosniff
            X-Frame-Options DENY
          }

          @gitea host gitea.workstation.zandoodle.me.uk
          handle @gitea {
            reverse_proxy unix//run/gitea/gitea.sock
          }

          @harmonia host cache.workstation.zandoodle.me.uk
          handle @harmonia {
            header {
              Content-Security-Policy "base-uri 'none'; default-src 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4'; style-src-elem https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css;"
            }
            reverse_proxy unix//run/harmonia.sock
          }

          handle {
            abort
          }
        '';
      };
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
    displayManager.gdm.autoSuspend = false;
    dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        bind-dynamic = true;
        conf-file = "${config.services.dnsmasq.package}/share/dnsmasq/trust-anchors.conf";
        dhcp-fqdn = true;
        dhcp-option = [ "option:mtu,9216" ];
        dhcp-range = [ "192.168.4.20,192.168.4.250" "fd80:1234::20,fd80:1234::ffff:ffff:ffff:ffff" ];
        dhcp-rapid-commit = true;
        dnssec = true;
        domain = "home.arpa";
        enable-ra = true;
        interface = [ "enp2s0" ];
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
          DOMAIN = "workstation.zandoodle.me.uk";
          HTTP_ADDR = "/run/gitea/gitea.sock";
          PROTOCOL = "http+unix";
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
    kerberos_server = {
      enable = true;
      settings = {
        kdcdefaults.spake_preauth_kdc_challenge = "edwards25519";
        realms."WORKSTATION.ZANDOODLE.ME.UK" = {
          acl = [
            {
              access = "all";
              principal = "*/admin";
            }
            {
              access = "all";
              principal = "max/zandoodle.me.uk@ZANDOODLE.ME.UK";
            }
            {
              access = "all";
              principal = "max/workstation.zandoodle.me.uk";
            }
          ];
          supported_enctypes = "aes256-sha2";
          master_key_type = "aes256-sha2";
        };
      };
    };
    knot = {
      enable = true;
      keyFiles = [
        "/etc/knot/workstation.tsig"
        "/run/credentials/knot.service/caddy"
      ];
      settings = {
        acl.caddy = {
          address = "::1";
          action = "update";
          key = "caddy";
          update-owner = "zone";
          update-type = "TXT";
        };
        policy = {
          acme-challenge = {
            ds-push = "orion";
            ksk-submission = "orion";
            propagation-delay = "10m";
            single-type-signing = true;
          };
          "max.home.arpa" = {
            manual = true;
            rrsig-lifetime = "12h";
            rrsig-refresh = "4h";
          };
        };
        remote.orion = {
          address = [
            "fd7a:115c:a1e0::1a01:5208@54"
            "100.122.82.8@54"
          ];
          key = "workstation";
        };
        server = {
          automatic-acl = true;
          listen = [
            "127.0.0.1@54"
            "::1@54"
            "172.28.10.244"
            "100.91.224.22"
            "fc9c:6b89:eec5:0d88:e258:0000:0000:0001"
            "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258"
            "fd7a:115c:a1e0:ab12:4843:cd96:625b:e016"
          ];
        };
        submission.orion.parent = [ "orion" ];
        zone = [
          {
            domain = "home.arpa";
            file = builtins.toFile "home.arpa.zone" ''
              @ SOA localhost. nobody.invalid. 0 3600 1200 604800 10800
              @ NS localhost.
              max NS dns.max
              dns.max A 172.28.10.244
              dns.max AAAA fc9c:6b89:eec5:0d88:e258:0000:0000:0001
              dns.max AAAA fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258
            '';
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
          }
          {
            acl = [ "caddy" ];
            dnssec-signing = true;
            dnssec-policy = "acme-challenge";
            domain = "_acme-challenge.workstation.zandoodle.me.uk";
            file = builtins.toFile "acme-challenge" ''
              @ soa workstation.zandoodle.me.uk. hostmaster.zandoodle.me.uk 0 14400 3600 604800 86400
              @ ns dns.zandoodle.me.uk.
            '';
            notify = "orion";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "TXT";
            zonefile-sync = -1;
            zonemd-generate = "zonemd-sha512";
          }
          {
            dnssec-signing = true;
            dnssec-policy = "max.home.arpa";
            domain = "max.home.arpa";
            file = "/etc/knot/max.home.arpa.zone";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-sync = -1;
            zonemd-generate = "zonemd-sha512";
          }
        ];
      };
    };
    minecraft-server = {
      enable = true;
      declarative = true;
      eula = true;
      package =
        inputs.nix-minecraft.legacyPackages.x86_64-linux.fabricServers.fabric-1_21_10;
      serverProperties = {
        server-ip = "127.0.0.1";
        server-port = 25564;
      };
    };
    nfs = {
      server = {
        enable = true;
        hostName = "workstation.zandoodle.me.uk,max-nixos-workstation-zerotier-ipv4,max-nixos-workstation-zerotier-6plane,max-nixos-workstation-zerotier-rfc4193,192.168.4.1";
        exports = ''
          /Big/shared -mp=/Big,sec=krb5p,rw,all_squash,anonuid=1000,anongid=100,async *
          /Big/shared/riscv/star64_root 192.168.4.0/24(rw,no_root_squash,mp=/Big)
          /nix 192.168.4.0/24(ro,no_root_squash)
        '';
      };
    };
    openssh = {
      settings = {
        GSSAPIAuthentication = true;
        GSSAPIStrictAcceptorCheck = false;
      };
      startWhenNeeded = true;
    };
    ratbagd = {
      enable = true;
    };
    unbound = {
      resolveLocalQueries = false;
      settings = {
        forward-zone = [
          {
            name = "broadband";
            forward-addr = [
              "fc9c:6b89:eed9:c2b9:c567:1:192.168.1.1"
            ];
          }
          {
            name = "zandoodle.me.uk";
            forward-addr = [
              "100.122.82.8"
              "fd7a:115c:a1e0::1a01:5208"
            ];
            forward-first = true;
          }
        ];
        server = {
          domain-insecure = ["broadband"];
          local-zone = [
            "168.192.in-addr.arpa nodefault"
            "d.f.ip6.arpa nodefault"
          ];
          interface = ["127.0.0.53"];
          qname-minimisation = false;
        };
        stub-zone = [
          {
            name = "max.home.arpa";
            stub-addr = "127.0.0.1@54";
          }
        ];
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
          vlan = [ "guest" "shadow-lan" ];
        };
        "10-enp2s0" = {
          address = ["192.168.4.1/24" "fd80:1234::1/64"];
          matchConfig = {
            Name = "enp2s0";
          };
          linkConfig = {
            MTUBytes = 9216;
            RequiredForOnline = false;
          };
          domains = [ "home.arpa" ];
          dns = [ "192.168.4.1" "fd80:1234::1" ];
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
        "10-tayga" = {
          address = [ "192.0.0.1/31" "fd64::/64" ];
          matchConfig.Name = "tayga";
          routes = [
            {
              Metric = 2048;
              Destination = "192.168.0.0/16";
              MTUBytes = 1480;
            }
          ];
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
          "10-tayga" = {
            netdevConfig = {
              Kind = "tun";
              Name = "tayga";
            };
            tunConfig = {
              User = "tayga";
              Group = "tayga";
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
          IPAddressAllow = "100.109.29.126 172.28.10.244 fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258/88 fc9c:6b89:eec5:0d88:e258:0000:0000:0001/40 192.168.4.1/24";
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
      caddy.serviceConfig = {
        LoadCredential =
          map (attr: "tsig-${attr}:/run/keymgr/caddy-${attr}") [ "id" "secret" "algorithm"];
        RuntimeDirectory = "caddy";
      };
      dnsmasq = {
        preStart = lib.mkForce "";
        serviceConfig = {
          AmbientCapabilities = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          CapabilityBoundingSet = "CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BROADCAST";
          IPAddressAllow = "0.0.0.0 255.255.255.255 fe80::/10 ff02::1 127.0.0.53 fd80:1234::/64 192.168.4.0/24";
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
      gen-tsig = {
        before = [ "knot.service" "caddy.service" ];
        requiredBy = [ "knot.service" "caddy.service" ];
        confinement.enable = true;
        serviceConfig = {
          CapabilityBoundingSet = "";
          DynamicUser = true;
          Group = "keymgr";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          PrivateNetwork = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemainAfterExit = true;
          RestrictAddressFamilies = true;
          RestrictRealtime = true;
          RuntimeDirectory = "keymgr";
          RuntimeDirectoryPreserve = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources"];
          Type = "oneshot";
          UMask = "077";
          User = "keymgr";
        };
        script = ''
          ${lib.getExe' pkgs.knot-dns "keymgr"} -t caddy >/run/keymgr/caddy
          for attr in id algorithm secret; do
            ${lib.getExe pkgs.yq} -r .key.[]."$attr" </run/keymgr/caddy >/run/keymgr/caddy-"$attr"
          done
        '';
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
      knot.serviceConfig.LoadCredential = "caddy:/run/keymgr/caddy";
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
            hash = "sha256-yC5pMBLsi4BnUq4CxTfwe4MGTqoBg04ZaRrsBC3Ds3Y=";
            url =
              "https://cdn.modrinth.com/data/9eGKb6K1/versions/BjR2lc4k/voicechat-fabric-1.21.10-2.6.6.jar";
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
        onFailure = [
          "latest-system-restart.target"
          "knot-reload.target"
        ];
        onSuccess = [
          "latest-system-restart.target"
          "knot-reload.target"
        ];
        serviceConfig = {
          RuntimeDirectory = "nixos-upgrade-all";
          RuntimeDirectoryMode = "0700";
          StateDirectory = "nixos-upgrade-all";
          StateDirectoryMode = "0755";
        };
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
          cd /run/nixos-upgrade-all

          git -c \
            "core.sshCommand=ssh -i /var/lib/nixos-upgrade-all/id_ed25519" \
            clone --single-branch -b main \
            gitea@workstation.zandoodle.me.uk:zandoodle/nixos-config

          cd nixos-config

          git checkout -b update

          nix flake update --commit-lock-file

          if config_all="$(nix build \
            git+file:///run/nixos-upgrade-all/nixos-config#systems-with-zone \
            --no-link --print-out-paths --refresh --no-write-lock-file \
            --option store daemon)"; then
            git checkout main
            git merge --ff update
            git -c \
              "core.sshCommand=ssh -i /var/lib/nixos-upgrade-all/id_ed25519" \
              push
            update_failed=no
          else
            git checkout main
            config_all="$(nix build \
              git+file:///run/nixos-upgrade-all/nixos-config#systems-with-zone \
              --no-link --print-out-paths --refresh --no-write-lock-file \
              --option store daemon)"
            update_failed=yes
            echo "Failed to update lock file" >&2
          fi

          nix-env -p /nix/var/nix/profiles/all --set "''${config_all}"

          config="$(readlink -e \
            "''${config_all}/systems/${config.networking.hostName}")"
          nix-env -p /nix/var/nix/profiles/system --set "''${config}"

          booted=$(readlink /run/booted-system/{kernel,kernel-modules})
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
          if [ "''${update_failed}" = yes ]; then
            echo "Failed to update lock file" >&2
            # Temporary failure
            exit 75
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
      tayga = {
        after = [ "sys-subsystem-net-devices-tayga.device" ];
        confinement.enable = true;
        restartTriggers = [ config.environment.etc."tayga/tayga.conf".source ];
        serviceConfig = {
          BindReadOnlyPaths = [
            "${config.environment.etc."tayga/tayga.conf".source}:/etc/tayga/tayga.conf"
            "/dev/net/tun"
          ];
          CapabilityBoundingSet = "";
          DeviceAllow = "/dev/net/tun";
          ExecStart = "${lib.getExe pkgs.tayga} -d -c /etc/tayga/tayga.conf";
          Group = "tayga";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          Restart = "on-failure";
          RestrictAddressFamilies = "AF_INET";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          StateDirectory = "tayga";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          UMask = "077";
          User = "tayga";
        };
        wantedBy = [ "multi-user.target" ];
        wants = [ "sys-subsystem-net-devices-tayga.device" ];
      };
      knot-reload = {
        after = [ "knot.service" ];
        confinement.enable = true;
        requires = [ "knot.service" ];
        restartTriggers = map (zone: config.environment.etc."knot/${zone}".source) [
          "max.home.arpa.zone"
        ];
        serviceConfig = {
          BindReadOnlyPaths = "/run/knot/knot.sock";
          CapabilityBoundingSet = "";
          ExecStart = "${lib.getExe' pkgs.knot-dns "knotc"} zone-reload";
          Group = "knot";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateNetwork = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemainAfterExit = true;
          RemoveIPC = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          Type = "oneshot";
          User = "knot";
        };
        wantedBy = [ "multi-user.target" ];
      };
    };
    sockets = {
      harmonia-proxy = {
        listenStreams = [
          "172.28.10.244:8080"
          "[fd80:56c2:e21c:3d4b:c99:93c5:d88:e258]:8080"
          "[fc9c:6b89:eec5:d88:e258::1]:8080"
          "/run/harmonia.sock"
        ];
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
        wantedBy = [ "sockets.target" ];
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
      knot-reload = {
        description = "Restart knot-reload service";
        conflicts = [ "knot-reload.service" ];
        unitConfig.StopWhenUnneeded = true;
        onSuccess = [ "knot-reload.service" ];
      };
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
          mbuffer
          zstd
        ];
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
      tayga = {
        group = "tayga";
        isSystemUser = true;
      };
    };
    groups = {
      ddns = {};
      tayga = {};
    };
  };
}
