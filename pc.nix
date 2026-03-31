{ config, inputs, lib, pkgs, ... }:

let
  dnsdist =
    inputs.nixpkgs-unstable.legacyPackages.${config.nixpkgs.system}.dnsdist;
in

{
  imports = [
    ./remote.nix
    ./hardware-configuration/pc.nix
    ./zone.nix
  ];
  boot = {
    kernelPackages = lib.mkForce pkgs.linuxPackages;
    kernelParams = [
      "console=ttyS0,115200"
      "console=tty0"
    ];
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
    };
    tmp = {
      tmpfsSize = "100%";
      useTmpfs = true;
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
        "dnsdist/dnsdist.conf".text = ''
          -- listen on local addresses
          addLocal("0.0.0.0:53")
          addLocal("[::]:53")

          newServer({
            address = "[::1]:54",
            name = "knot",
            pool = "auth",
            healthCheckMode = "lazy"
          })
          newServer({
            address = "[::1]:55",
            name = "unbound",
            pool = "recursive",
            healthCheckMode = "lazy"
          })

          addAction(RDRule(), PoolAction("recursive"))
          addAction(AllRule(), PoolAction("auth"))
        '';
        "tayga/tayga.conf".text = ''
          tun-device tayga
          ipv4-addr 192.0.0.2
          ipv6-addr fd64::1
          map 192.0.0.1 fd64::2
          prefix fd09:a389:7c1e:3::/64
        '';
      };
  };
  hardware = {
    graphics.extraPackages = [
      pkgs.intel-media-driver
      pkgs.nvidia-vaapi-driver
    ];
    nvidia.open = true;
  };
  networking = {
    firewall = {
      allowedTCPPorts = [ 53 54 55 8053 ];
      allowedUDPPorts = [ 53 54 55 8053 ];
      extraForwardRules = ''
        iifname tayga oifname shadow-lan accept
        iiftype ipip6 oifname {internet, guest, "shadow-lan"} accept
      '';
      filterForward = true;
      interfaces = {
        internet = {
          allowedTCPPorts = [ 179 9943 9944 ];
          allowedUDPPorts = [ 9943 9944 ];
        };
        guest.allowedTCPPorts = [ 179 ];
        "shadow-lan".allowedTCPPorts = [ 179 ];
        tailscale0.allowedTCPPorts = [ 80 179 443 8000 ];
        tailscale0.allowedUDPPorts = [ 443 ];
      };
    };
    hostName = "max-nixos-pc";
    networkmanager.enable = false;
    nftables.tables = {
      tayga-nat66 = {
        family = "ip6";
        content = ''
          chain tayga-nat {
            type nat hook postrouting priority srcnat; policy accept
            iifname tayga oifname shadow-lan masquerade
          }
        '';
      };
      local-nat = {
        family = "inet";
        content = ''
          chain local-nat {
            type nat hook postrouting priority srcnat; policy accept
            fib saddr . mark type != local oifname {internet, guest, "shadow-lan"} masquerade
          }
        '';
      };
    };
    useNetworkd = true;
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
    bird = {
      enable = true;
      package =
        inputs.nixpkgs-unstable.legacyPackages.${config.nixpkgs.system}.bird3.overrideAttrs
        ({ patches ? [], ... }: {
          patches = patches ++ [ ./bird-aspa.patch ];
        });
      config = ''
        router id 192.168.11.5;
        roa4 table r4;
        roa6 table r6;
        aspa table at;
        mpls domain mdom;
        mpls table mtab;
        vpn4 table vtab4;
        vpn6 table vtab6;
        ipv4 table local4;
        ipv6 table local6;
        function verify_in(bool upstream) {
          case net.type {
            NET_IP4: {
              if (roa_check(r4) = ROA_INVALID) then {
                reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
              }
            }
            NET_IP6: {
              if (roa_check(r6) = ROA_INVALID) then {
                reject "Ignore RPKI invalid ", net, " for ASN ", bgp_path.last;
              }
            }
          }
          if (aspa_check(at, bgp_path, upstream) = ASPA_INVALID) then {
            reject "Ignore ASPA invalid ", net, " for ASN ", bgp_path.last;
          }
        }
        filter provider_in {
          if !defined(bgp_otc) then {
            bgp_otc = bgp_path.first;
          }
          verify_in(false);
          accept;
        }
        filter peer_in {
          if !defined(bgp_otc) then {
            bgp_otc = bgp_path.first;
          }
          if bgp_otc != bgp_path.first then reject;
          verify_in(true);
          accept;
        }
        filter customer_in {
          if defined(bgp_otc) then {
            reject;
          }
          verify_in(true);
          accept;
        }
        filter provider_out {
          if defined(bgp_otc) then {
            reject;
          }
          accept;
        }
        filter peer_out {
          if defined(bgp_otc) then {
            reject;
          }
          bgp_otc = 65001;
          accept;
        }
        filter customer_out {
          if !defined(bgp_otc) then {
            bgp_otc = 65001;
          }
          accept;
        }
        template bgp {
          local as 65002;
          require roles on;
          enforce first as on;
          mpls {label policy aggregate;};
          ipv4 mpls {
            extended next hop on;
            import table on;
          };
          ipv6 mpls {
            import table on;
          };
          vpn4 mpls {
            extended next hop on;
            import table on;
          };
          vpn6 mpls {
            import table on;
          };
        }
        template bgp orion from bgp1 {
          local role customer;
          ipv4 mpls {
            export filter provider_out;
            import filter provider_in;
          };
          ipv6 mpls {
            export filter provider_out;
            import filter provider_in;
          };
          vpn4 mpls {
            export filter provider_out;
            import filter provider_in;
          };
          vpn6 mpls {
            export filter provider_out;
            import filter provider_in;
          };
        }
        protocol bgp orion_internet from orion {
          neighbor fe80::7006:83ff:feff:5d0b%internet as 65001;
          interface "internet";
        }
        protocol bgp orion_shadow from orion {
          neighbor fe80::7006:83ff:feff:5d0b as 65001;
          interface "shadow-lan";
          ipv4 mpls {preference 90;};
          ipv6 mpls {preference 90;};
          vpn4 mpls {preference 90;};
          vpn6 mpls {preference 90;};
        }
        protocol bgp orion_guest from orion {
          neighbor fe80::7006:83ff:feff:5d0c%guest as 65001;
          ipv4 mpls {preference 80;};
          ipv6 mpls {preference 80;};
          vpn4 mpls {preference 80;};
          vpn6 mpls {preference 80;};
        }
        protocol bgp workstation from bgp1 {
          local fe80::5 as 65002;
          neighbor fe80::2 as 65000;
          local role provider;
          require roles on;
          interface "workstation-tnl";
          ipv6 mpls {
            export filter customer_out;
            import filter customer_in;
          };
          ipv4 mpls {
            export filter customer_out;
            import filter customer_in;
          };
          vpn6 mpls {
            export filter customer_out;
            import filter customer_in;
          };
          vpn4 mpls {
            export filter customer_out;
            import filter customer_in;
          };
        }
        protocol device {

        }
        protocol direct {
          ipv4 {
            table local4;
          };
          ipv6 {
            import where net.len != 128;
            table local6;
          };
          interface "internet", "guest", "shadow-lan";
        }
        protocol pipe {
          table master4;
          peer table local4;
          import filter {
            preference = 70;
            accept;
          };
          export filter {
            preference = 70;
            accept;
          };
        }
        protocol pipe {
          table master6;
          peer table local6;
          import filter {
            preference = 70;
            accept;
          };
          export filter {
            preference = 70;
            accept;
          };
        }
        protocol kernel {
          ipv4 {
            table local4;
            export filter {
              if source = RTS_DEVICE then
                reject;
              krt_prefsrc = 192.168.11.5;
              accept;
            };
          };
        }
        protocol kernel {
          ipv6 {
            table local6;
            export filter {
              if source = RTS_DEVICE then
                reject;
              krt_prefsrc = fd09:a389:7c1e:6::5;
              accept;
            };
          };
        }
        protocol kernel {
          mpls {export all;};
        }
        protocol rpki {
          roa4 { table r4; };
          roa6 { table r6; };
          aspa { table at; };

          remote "localhost";
        }
        protocol static {
          ipv4;
          route 192.168.11.5/32 via "lo";
        }
        protocol static {
          ipv6;
          route fd09:a389:7c1e:6::5/128 via "lo";
        }
      '';
    };
    bird-lg.proxy = {
      enable = true;
      listenAddresses = [ "[::]:8000" ];
    };
    btrbk = {
      instances = {
        btrbk = {
          settings = {
            volume = {
              "ssh://workstation.zandoodle.me.uk/nexus" = {
                subvolume = {
                  "@NixOS" = {
                    snapshot_name = "@NixOS-for-pc";
                  };
                };
                target = "/HDD/backups/workstation";
                snapshot_preserve = "1d 1w";
                snapshot_preserve_min = "latest";
                incremental = "strict";
              };
              "ssh://workstation.zandoodle.me.uk/Big" = {
                subvolume = {
                  "shared" = {
                    snapshot_name = "shared-for-pc";
                  };
                };
                target = "/HDD/backups/workstation";
                snapshot_preserve = "1d 1w";
                snapshot_preserve_min = "latest";
                incremental = "strict";
              };
              "/nexus" = {
                target = {
                  "/HDD/backups/pc" = {};
                };
              };
            };
          };
        };
      };
    };
    caddy = {
      enable = true;
      globalConfig = ''
        acme_ca "https://acme-v02.api.letsencrypt.org/directory"
        dns rfc2136 {
          key_name {file./run/credentials/caddy.service/tsig-id}
          key_alg {file./run/credentials/caddy.service/tsig-algorithm}
          key {file./run/credentials/caddy.service/tsig-secret}
          server [::1]:54
        }
        key_type p384
        preferred_chains {
          root_common_name "ISRG Root X2"
        }
      '';
      package = pkgs.caddy.withPlugins {
        plugins = [ "github.com/caddy-dns/rfc2136@v1.0.0" ];
        hash = "sha256-S078bVfUolEa6icL2hJgTTzZ8r7+j+D9lfyOc5SCvzQ=";
      };
      virtualHosts."pc.int.zandoodle.me.uk".extraConfig = ''
        tls {
          issuer acme {
            dns
            profile shortlived
          }
        }

        header {
          Cross-Origin-Resource-Policy same-origin
          Referrer-Policy no-referrer
          Strict-Transport-Security "max-age=31536000; includeSubdomains; preload"
          X-Content-Type-Options nosniff
          X-Frame-Options DENY
        }

        reverse_proxy [::1]:11434 {
          header_up Host localhost
        }
      '';
    };
    displayManager.gdm.autoSuspend = false;
    ip-mesh.self-tunnel-addresses = [ "fe80::5/64" ];
    knot = {
      enable = true;
      keyFiles = [
        "/etc/knot/pc.tsig"
        "/run/credentials/knot.service/caddy"
      ];
      settings = {
        acl = {
          caddy = {
            address = "::1";
            action = "update";
            key = "caddy";
            update-owner = "zone";
            update-owner-match = "equal";
            update-type = "TXT";
          };
          transfer = {
            action = "transfer";
            address = [
              "10.0.0.0/8"
              "100.64.0.0/10"
              "127.0.0.0/8"
              "169.254.0.0/16"
              "192.168.0.0/16"
              "172.16.0.0/12"
              "::1/128"
              "fc00::/7"
              "fe80::/10"
            ];
          };
        };
        mod-queryacl.local.address = [
          "10.0.0.0/8"
          "100.64.0.0/10"
          "127.0.0.0/8"
          "169.254.0.0/16"
          "192.168.0.0/16"
          "172.16.0.0/12"
          "::1/128"
          "fc00::/7"
          "fe80::/10"
        ];
        policy = {
          acme-challenge = {
            ds-push = "orion";
            ksk-lifetime = "14d";
            ksk-submission = "subdomain";
            single-type-signing = true;
          };
        };
        remote = {
          "ns1.first-ns.de".address = "2a01:4f8:0:a101::a:1";
          orion = {
            address = "fd7a:115c:a1e0::1a01:5208@54";
            key = "pc";
          };
          "robotns2.second-ns.de".address = "2a01:4f8:0:1::5ddc:2";
          "robotns3.second-ns.com".address = "2001:67c:192c::add:a3";
        };
        server = {
          automatic-acl = true;
          identity = "pc.zandoodle.me.uk";
          listen = [ "0.0.0.0@54" "::@54" ];
          nsid = "pc.zandoodle.me.uk";
          tcp-fastopen = true;
          tcp-reuseport = true;
        };
        submission.subdomain.parent = [ "orion" ];
        template = {
          catalog-zone = {
            acl = [ "transfer" ];
            master = "orion";
            module = "mod-queryacl/local";
            semantic-checks = true;
          };
          global = {
            acl = [ "transfer" ];
            dnssec-validation = true;
            master = "orion";
            semantic-checks = true;
            zonemd-verify = true;
          };
          default.global-module = ["mod-cookies" "mod-rrl"];
        };
        zone = {
          catz = {
            master = "orion";
            catalog-role = "interpret";
            catalog-template = ["catalog-zone" "global"];
          };
          "_acme-challenge.pc.int.zandoodle.me.uk" = {
            acl = [ "caddy" "transfer" ];
            dnssec-signing = true;
            dnssec-policy = "acme-challenge";
            file = builtins.toFile "acme-challenge" ''
              @ soa pc.int.zandoodle.me.uk. hostmaster.zandoodle.me.uk. 0 14400 3600 604800 86400
              @ ns dns.zandoodle.me.uk.
            '';
            notify = "orion";
            semantic-checks = true;
            journal-content = "all";
            zonefile-load = "difference-no-serial";
            zonefile-skip = "TXT";
            zonefile-sync = -1;
            zonemd-generate = "zonemd-sha512";
          };
        };
      };
    };
    ollama = {
      enable = true;
      host = "[::1]";
      acceleration = "cuda";
    };
    ratbagd = {
      enable = true;
    };
    routinator = {
      enable = true;
      package =
        pkgs.routinator.overrideAttrs (
          { patches ? [], ... }: {
            patches = patches ++ [ ./routinator.patch ];
          });
      settings = {
        enable-aspa = true;
        extra-tals-dir = ./tals;
        no-rir-tals = true;
        systemd-listen = true;
      };
    };
    unbound.settings = {
      forward-zone = [
        {
          name = "broadband";
          forward-addr = [ "192.168.1.1" ];
        }
        {
          name = "arpa";
          forward-addr =
            "fd7a:115c:a1e0::1a01:5208#local-tailscale.zandoodle.me.uk";
          forward-first = true;
          forward-tls-upstream = true;
        }
        {
          name = "in-addr.arpa";
          forward-addr =
            "fd7a:115c:a1e0::1a01:5208#local-tailscale.zandoodle.me.uk";
          forward-first = true;
          forward-tls-upstream = true;
        }
        {
          name = "ip6.arpa";
          forward-addr =
            "fd7a:115c:a1e0::1a01:5208#local-tailscale.zandoodle.me.uk";
          forward-first = true;
          forward-tls-upstream = true;
        }
      ];
      server = {
        domain-insecure = [
          "home.arpa"
          "168.192.in-addr.arpa"
          "d.f.ip6.arpa"
          "root-servers.net"
        ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa") 64;
        interface = [ "127.0.0.1@55" "::@55" ];
        local-zone = [
          "168.192.in-addr.arpa nodefault"
          "d.f.ip6.arpa nodefault"
        ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa nodefault") 64;
      };
      stub-zone = [
        {
          name = "max.home.arpa";
          stub-host = "workstation.zandoodle.me.uk";
        }
      ] ++ (map (zone:
          {
            name = zone;
            stub-addr = [
              "::1@54"
              "127.0.0.1@54"
            ];
            stub-first = true;
          }) ([
            "."
            "168.192.in-addr.arpa"
            "_acme-challenge.pc.int.zandoodle.me.uk"
            "_acme-challenge.workstation.zandoodle.me.uk"
            "_acme-challenge.zandoodle.me.uk"
            "arpa"
            "compsoc-dev.com"
            "d.f.ip6.arpa"
            "home.arpa"
            "in-addr.arpa"
            "int.zandoodle.me.uk"
            "ip6.arpa"
            "ipv4only.arpa"
            "root-servers.net"
            "zandoodle.me.uk"
          ] ++ lib.genList (i: "${toString (i+64)}.100.in-addr.arpa") 64));
    };
    xserver = {
      videoDrivers = [
        "nvidia"
      ];
    };
  };
  systemd = {
    network = {
      config.networkConfig = {
        IPv4Forwarding = true;
        IPv6Forwarding = true;
      };
      enable = true;
      links = {
        "10-eno1" = {
          matchConfig = {
            MACAddress = "40:b0:76:de:79:dc";
          };
          linkConfig = {
            NamePolicy = "keep kernel database onboard slot path";
            AlternativeNamesPolicy = "database onboard slot path";
            TCPSegmentationOffload = false;
          };
        };
      };
      netdevs = {
        "10-guest" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "guest";
          };
          vlanConfig.Id = 10;
        };
        "10-internet" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "internet";
          };
          vlanConfig.Id = 1;
        };
        "10-shadow-lan" = {
          netdevConfig = {
            Kind = "vlan";
            Name = "shadow-lan";
          };
          vlanConfig.Id = 20;
        };
        "10-tayga" = {
          netdevConfig = {
            Kind = "tun";
            Name = "tayga";
          };
          tunConfig = {
            Group = "tayga";
            User = "tayga";
          };
        };
      };
      networks = {
        "10-enp2s0f2" = {
          linkConfig.ARP = false;
          name = "enp2s0f2";
          vlan = [ "guest" "internet" "shadow-lan" ];
        };
        "10-guest" = {
          DHCP = "yes";
          dhcpV4Config.RouteMetric = 1536;
          extraConfig = ''
            [Network]
            MPLSRouting = true
          '';
          ipv6AcceptRAConfig.RouteMetric = 2048;
          linkConfig.ARP = true;
          name = "guest";
          networkConfig.IPv6AcceptRA = true;
        };
        "10-internet" = {
          DHCP = "yes";
          extraConfig = ''
            [Network]
            MPLSRouting = true
          '';
          linkConfig.ARP = true;
          name = "internet";
          networkConfig.IPv6AcceptRA = true;
        };
        "10-lo" = {
          address = [ "192.168.11.5/32" "fd09:a389:7c1e:6::5/128" ];
          name = "lo";
          networkConfig.KeepConfiguration = "static";
        };
        "10-shadow-lan" = {
          DHCP = "yes";
          dhcpV4Config.RouteMetric = 1536;
          extraConfig = ''
            [Network]
            MPLSRouting = true
          '';
          ipv6AcceptRAConfig.RouteMetric = 2048;
          linkConfig.ARP = true;
          name = "shadow-lan";
          networkConfig.IPv6AcceptRA = true;
        };
        "10-tayga" = {
          address = [ "192.0.0.1/30" "fd64::/64" ];
          matchConfig.Name = "tayga";
          routes = [
            {
              Destination = "0.0.0.0/0";
              Metric = 2048;
              MTUBytes = 1480;
            }
          ];
        };
      };
      wait-online.enable = lib.mkForce true;
    };
    packages = [
      dnsdist
    ];
    services = {
      btrbk-btrbk = {
        unitConfig = {
          RequiresMountsFor = "/HDD/backups";
        };
        serviceConfig = {
          BindPaths = [ "/HDD/backups" ];
          PrivateNetwork = lib.mkForce false;
          IPAddressAllow = "::1 127.0.0.1 100.91.224.22 fd7a:115c:a1e0:ab12:4843:cd96:625b:e016";
          RestrictSUIDSGID = lib.mkForce false;
          CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
          AmbientCapabilities = [ "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FSETID CAP_SETFCAP CAP_MKNOD" ];
        };
      };
      caddy.serviceConfig.LoadCredential =
        map (attr: "tsig-${attr}:/run/keymgr/caddy-${attr}") [
          "id"
          "secret"
          "algorithm"
        ];
      dnsdist = {
        serviceConfig = {
          # Override the dnsdist service to use /etc/dnsdist/dnsdist.conf
          ExecStart = [
            ""
            "${lib.getExe dnsdist} --supervised --disable-syslog --config /etc/dnsdist/dnsdist.conf"
          ];
          ExecStartPre = [
            ""
            "${lib.getExe dnsdist} --check-config --config /etc/dnsdist/dnsdist.conf"
          ];

          # Run as a dedicated user
          User = "dnsdist";
          Group = "dnsdist";
        };

        # Restart dnsdist when the config changes
        restartTriggers = [ config.environment.etc."dnsdist/dnsdist.conf".source ];

        # Restart dnsdist immediatly
        startLimitIntervalSec = 0;

        # Start dnsdist on boot
        wantedBy = [ "multi-user.target" ];
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
          RestrictAddressFamilies = "none";
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
      knot.serviceConfig.LoadCredential = "caddy:/run/keymgr/caddy";
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
      unbound = {
        after = [ "zone-home-test.service" ];
        wants = [ "zone-home-test.service" ];
      };
    };
    sockets = {
      routinator = {
        listenStreams = [ "[::]:323" ];
        wantedBy = [ "routinator.service" ];
      };
    };
    tmpfiles = {
      rules = [
        "v /HDD/backups 700 btrbk btrbk"
        "d /HDD/backups/pc"
        "d /HDD/backups/workstation"
      ];
    };
  };

  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];

  users = {
    groups = {
      dnsdist = {};
      tayga = {};
    };
    users = {
      btrbk = {
        packages = with pkgs; [
          zstd
        ];
      };
      dnsdist = {
        group = "dnsdist";
        isSystemUser = true;
      };
      max = {
        packages = with pkgs; [
          piper
        ];
      };
      tayga = {
        isSystemUser = true;
        group = "tayga";
      };
    };
  };

}
