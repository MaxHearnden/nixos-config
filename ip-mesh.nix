{ config, inputs, lib, pkgs, ... }:

let
  cfg = config.services.ip-mesh;
  types = lib.types;
  ingress_filters = {
    "complex" = "filter complex_in";
    "customer" = "filter provider_in";
    "peer" = "filter peer_in";
    "provider" = "filter customer_in";
  };
  egress_filters = {
    "complex" = "all";
    "customer" = "filter provider_out";
    "peer" = "filter peer_out";
    "provider" = "filter customer_out";
  };
  peerModule = types.submodule ({config, ...}: {
    options = {
      address = lib.mkOption {
        type = types.str;
      };
      asn = lib.mkOption {
        type = types.int;
      };
      enable = lib.mkEnableOption "The protocol to the peer" // {
        default = true;
      };
      tunnel-address = lib.mkOption {
        type = types.str;
      };
      loopback-v4-address = lib.mkOption {
        type = types.str;
      };
      loopback-v6-address = lib.mkOption {
        type = types.str;
      };
      role = lib.mkOption {
        default = null;
        type = types.nullOr types.str;
      };
      ingress_filter = lib.mkOption {
        default = ingress_filters.${config.role or "complex"};
        type = types.str;
      };
      egress_filter = lib.mkOption {
        default = egress_filters.${config.role or "complex"};
        type = types.str;
      };
    };
  });
in

{
  options = {
    services.ip-mesh = {
      enable = lib.mkEnableOption "A ip6tnl based mesh";
      peers = lib.mkOption {
        type = lib.types.attrsOf peerModule;
      };
      self = lib.mkOption {
        type = lib.types.str;
      };
      self-as = lib.mkOption {
        default = cfg.peers.${cfg.self}.asn;
        type = lib.types.int;
      };
      self-tunnel-address = lib.mkOption {
        default = cfg.peers.${cfg.self}.tunnel-address;
        type = lib.types.str;
      };
      self-address = lib.mkOption {
        default = cfg.peers.${cfg.self}.address;
        type = lib.types.str;
      };
      self-loopback-v4-address = lib.mkOption {
        default = cfg.peers.${cfg.self}.loopback-v4-address;
        type = lib.types.str;
      };
      self-loopback-v6-address = lib.mkOption {
        default = cfg.peers.${cfg.self}.loopback-v6-address;
        type = lib.types.str;
      };
    };
  };
  config = lib.mkIf cfg.enable {
    boot = {
      kernel.sysctl."net.mpls.platform_labels" = 1048575;
      kernelModules = [ "mpls_router" "mpls_iptunnel" "mpls_gro" ];
    };
    networking.firewall.interfaces = lib.mapAttrs' (name: _: {
      name = "${name}-tnl";
      value.allowedTCPPorts = [ 179 ];
    }) (lib.filterAttrs (name: _: name !=
      config.services.ip-mesh.self) config.services.ip-mesh.peers);
    services = {
      bird = {
        enable = true;
        package =
          inputs.nixpkgs-unstable.legacyPackages.${config.nixpkgs.system}.bird3.overrideAttrs
          ({ patches ? [], ... }: {
            patches = patches ++ [ ./bird-aspa.patch ./bird-mpls-fix.patch ];
          });
      };
      bird-cfg = {
        enable = true;
        files = {
          "10-ip-mesh-defines".text = ''
            router id ${cfg.self-loopback-v4-address};
            define self_as = ${toString cfg.self-as};
            define self_loopback_v4 = ${cfg.self-loopback-v4-address};
            define self_loopback_v6 = ${cfg.self-loopback-v6-address};
          '';
          "20-tables".text = ''
          aspa table at;
          mpls domain mdom;
          mpls table mtab;
          roa4 table r4;
          roa6 table r6;
          vpn4 table vtab4;
          vpn6 table vtab6;
          '';
          "25-birdlib".source = ./birdlib.conf;
          "30-ip-mesh-template".text = ''
            template bgp ip_tunnel {
              local ${cfg.self-tunnel-address} as self_as;
              enforce first as on;
              ipv4 mpls {
                export all;
                extended next hop on;
                import filter complex_in;
                import table on;
                require extended next hop on;
              };
              ipv6 mpls {
                export all;
                import table on;
                import filter complex_in;
              };
              mpls {label policy aggregate;};
              vpn4 mpls {
                export all;
                extended next hop on;
                import filter complex_in;
                import table on;
                require extended next hop on;
              };
              vpn6 mpls {
                export all;
                import table on;
                import filter complex_in;
              };
            }
          '';
          "40-device".text = ''
            protocol device {}
          '';
          "50-kernel-ip".text = ''
            protocol kernel {
              ipv4 {
                export filter {
                  if source = RTS_DEVICE then
                    reject;
                  krt_prefsrc = self_loopback_v4;
                  accept;
                };
              };
            }
            protocol kernel {
              ipv6 {
                export filter {
                  if source = RTS_DEVICE then
                    reject;
                  krt_prefsrc = self_loopback_v6;
                  accept;
                };
              };
            }
          '';
          "50-kernel-mpls".text = ''
            protocol kernel {
              mpls {export all;};
            }
          '';
          "60-rpki".text = ''
            protocol rpki {
              aspa;
              roa4;
              roa6;
              remote "localhost";
            }
          '';
          "70-static".text = ''
            protocol static {
              ipv4;
              route ${cfg.self-loopback-v4-address}/32 via "lo";
            }
            protocol static {
              ipv6;
              route ${cfg.self-loopback-v6-address}/128 via "lo";
            }
          '';
        } // lib.mapAttrs' (name: peer: {
          name = "50-ip-mesh-${name}";
          value.text = ''
            protocol bgp ip_mesh_${name} from ip_tunnel {
              neighbor ${peer.tunnel-address} as ${toString peer.asn};
              interface "${name}-tnl";
              ${lib.optionalString (!isNull peer.role) ''
                local role ${peer.role};
              ''}
              ${lib.optionalString (!peer.enable) "disabled;"}
              ipv4 mpls {
                import ${peer.ingress_filter};
                export ${peer.egress_filter};
              };
              ipv6 mpls {
                import ${peer.ingress_filter};
                export ${peer.egress_filter};
              };
              vpn4 mpls {
                import ${peer.ingress_filter};
                export ${peer.egress_filter};
              };
              vpn6 mpls {
                import ${peer.ingress_filter};
                export ${peer.egress_filter};
              };
            }
          '';
        }) (lib.filterAttrs (name: _: name != cfg.self) cfg.peers);
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
    };
    systemd = {
      network = {
        netdevs = lib.mapAttrs' (name: peer: {
          name = "50-${name}-tnl";
          value = {
            netdevConfig = {
              Kind = "ip6tnl";
              Name = "${name}-tnl";
            };
            tunnelConfig = {
              Local = cfg.self-address;
              Remote = peer.address;
            };
          };
        }) (lib.filterAttrs (name: _: name !=
          config.services.ip-mesh.self) config.services.ip-mesh.peers);
        networks = lib.mapAttrs' (name: _: {
          name = "50-${name}-tnl";
          value = {
            address = ["${config.services.ip-mesh.self-tunnel-address}/64"];
            extraConfig = ''
              [Network]
              MPLSRouting = true
            '';
            name = "${name}-tnl";
            linkConfig = {
              MTUBytes = "1302";
              RequiredForOnline = false;
            };
          };
        }) (lib.filterAttrs (name: _: name !=
          config.services.ip-mesh.self) config.services.ip-mesh.peers)
        // {
          "40-lo" = {
            address = [
              "${cfg.self-loopback-v4-address}/32"
              "${cfg.self-loopback-v6-address}/128"
            ];
            name = "lo";
            networkConfig.KeepConfiguration = "static";
          };
          "40-tailscale" = {
            name = "tailscale0";
            linkConfig.RequiredForOnline = false;
            networkConfig = {
              DHCP = false;
              IPv6AcceptRA = false;
              KeepConfiguration = "static";
            };
            tunnel = lib.map (name: "${name}-tnl")
              (lib.filter (name: name != config.services.ip-mesh.self)
              (lib.attrNames config.services.ip-mesh.peers));
          };
        };
      };
      sockets = {
        routinator = {
          listenStreams = [ "[::]:323" ];
          wantedBy = [ "routinator.service" ];
        };
      };
    };
  };
}
