{ config, inputs, lib, pkgs, ... }:

let
  cfg = config.services.ip-mesh;
  types = lib.types;
  ingress-filter-fun = {
    "provider" = "customer_in_fun()";
    "peer" = "peer_in_fun()";
    "customer" = "provider_in_fun()";
    "complex" = "verify_in(false)";
  };
  egress-filter-fun = {
    "provider" = "customer_out_fun()";
    "peer" = "peer_out_fun()";
    "customer" = "provider_out_fun()";
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
      rr = lib.mkEnableOption "connecting to the route reflector";
      ingress_filter = lib.mkOption {
        default = "all";
        type = types.str;
      };
      egress_filter = lib.mkOption {
        default = "all";
        type = types.str;
      };
    };
  });
in

{
  options = {
    services.ip-mesh = {
      enable = lib.mkEnableOption "A ip6tnl based mesh";
      egress-filter-fun = lib.mkOption {
        default = egress-filter-fun.${config.role or "complex"} or null;
        type = types.nullOr types.str;
      };
      ingress-filter-fun = lib.mkOption {
        default = ingress-filter-fun.${config.role or "complex"} or null;
        type = types.nullOr types.str;
      };
      mesh-asn = lib.mkOption {
        type = lib.types.int;
      };
      mesh-role = lib.mkOption {
        default = null;
        type = types.nullOr types.str;
      };
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
      self-rr = lib.mkOption {
        default = cfg.peers.${cfg.self}.rr;
        type = lib.types.bool;
      };
    };
  };
  config = lib.mkIf cfg.enable {
    boot = {
      kernel.sysctl."net.mpls.platform_labels" = 1048575;
      kernelModules = [ "mpls_router" "mpls_iptunnel" "mpls_gso" ];
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
          inputs.nixpkgs-unstable.legacyPackages.${config.nixpkgs.system}.bird3;
      };
      bird-cfg = {
        enable = true;
        files = {
          "10-ip-mesh-defines".text = ''
            router id ${cfg.self-loopback-v4-address};
            define self_as = ${toString cfg.self-as};
            define mesh_as = ${toString cfg.mesh-asn};
            define self_loopback_v4 = ${cfg.self-loopback-v4-address};
            define self_loopback_v6 = ${cfg.self-loopback-v6-address};
          '';
          "20-tables".text = ''
            aspa table at;
            evpn table evpntab;
            mpls domain mdom;
            mpls table mtab;
            roa4 table r4;
            roa6 table r6;
            vpn4 table vtab4;
            vpn6 table vtab6;
            ipv6 table mesh_igp;
            evpn table evpn_mesh;
            ipv4 table mesh4;
            ipv6 table mesh6;
            vpn4 table vpn_mesh4;
            vpn6 table vpn_mesh6;
          '';
          "25-birdlib".source = ./birdlib.conf;
          "30-ip-mesh-igp".text = ''
            protocol static static_mesh_igp {
              ipv6 {
                table mesh_igp;
              };
          ''
          + (lib.concatMapAttrsStringSep "" (name: peer: ''
            route ${peer.address}/128 via "${name}-tnl";
          '') cfg.peers)
          + ''
            }
          '';
          "30-ip-mesh-template".text = ''
            template bgp ip_tunnel {
              local ${cfg.self-address} as mesh_as;
              neighbor internal;
              interface "tailscale0";
              onlink on;
              ${lib.optionalString (cfg.self-rr) "rr client on;"}
              default bgp_local_pref 95;
              direct;
              evpn {
                gateway recursive;
                igp table mesh_igp;
                import all; export all;
                table evpn_mesh;
              };
              ipv4 mpls {
                export all;
                extended next hop on;
                gateway recursive;
                igp table mesh_igp;
                import all;
                import table on;
                table mesh4;
                require extended next hop on;
              };
              ipv6 mpls {
                export all;
                gateway recursive;
                igp table mesh_igp;
                import table on;
                import all;
                table mesh6;
              };
              mpls {label policy aggregate;};
              vpn4 mpls {
                export all;
                extended next hop on;
                gateway recursive;
                igp table mesh_igp;
                import all;
                import table on;
                table vpn_mesh4;
                require extended next hop on;
              };
              vpn6 mpls {
                export all;
                gateway recursive;
                igp table mesh_igp;
                import table on;
                import all;
                table vpn_mesh6;
              };
            }
          '';
          "30-pipe-template".text = ''
            template pipe mesh_pipe {
              table master4;
              peer table mesh4;
              import filter {
                if source = RTS_BGP then {
                  if bgp_path ~ [ self_as ] then reject "Loop prevention", net,
                    bgp_path;
                  case bgp_path.first {
                    ${lib.concatMapAttrsStringSep "\n" (_: peer:
                      "${toString peer.asn}: if bgp_next_hop != ${peer.address}
                        then reject;") cfg.peers}
                    else: reject;
                  }
                  bgp_path.prepend(mesh_as);
                }
                ${lib.optionalString (!isNull cfg.ingress-filter-fun)
                  "${cfg.ingress-filter-fun};"}
              };
              export filter {
                if source = RTS_BGP then {
                  if bgp_path ~ [ mesh_as ] then reject "Loop prevention", net,
                    bgp_path;
                  bgp_path.prepend(self_as);
                }
                ${lib.optionalString (!isNull cfg.egress-filter-fun)
                  "${cfg.egress-filter-fun};"}
                bgp_next_hop = ${cfg.self-address};
              };
            }
          '';
          "40-device".text = ''
            protocol device {}
          '';
          "50-kernel-ip".text = ''
            template kernel ip4 {
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
          "50-pipe".text = ''
            protocol pipe from mesh_pipe { }
            protocol pipe from mesh_pipe {
              table master6;
              peer table mesh6;
            }
            protocol pipe from mesh_pipe {
              table evpntab;
              peer table evpn_mesh;
            }
            protocol pipe from mesh_pipe {
              table vtab4;
              peer table vpn_mesh4;
            }
            protocol pipe from mesh_pipe {
              table vtab6;
              peer table vpn_mesh6;
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
              neighbor ${peer.address};
              ${lib.optionalString (!peer.enable) "disabled;"}
              ${lib.optionalString (!peer.rr) "passive on;"}
            }
          '';
        }) (lib.filterAttrs (name: _: name != cfg.self) cfg.peers);
      };
      routinator = {
        enable = true;
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
      services.routinator.serviceConfig.NonBlocking = true;
      sockets = {
        routinator = {
          listenStreams = [ "[::]:323" ];
          wantedBy = [ "routinator.service" ];
        };
      };
    };
  };
}
