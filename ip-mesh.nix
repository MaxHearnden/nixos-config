{ config, lib, ... }: {
  options = {
    services.ip-mesh = {
      peers = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
      };
      self = lib.mkOption {
        type = lib.types.str;
      };
      self-address = lib.mkOption {
        default = config.services.ip-mesh.peers.${config.services.ip-mesh.self};
        type = lib.types.str;
      };
    };
  };
  config = {
    systemd.network = {
      netdevs = lib.mapAttrs' (name: address: {
        name = "50-${name}-tnl";
        value = {
          netdevConfig = {
            Kind = "ip6tnl";
            Name = "${name}-tnl";
          };
          tunnelConfig = {
            Independent = true;
            Local = config.services.ip-mesh.self-address;
            Remote = address;
          };
        };
      }) (lib.filterAttrs (name: _: name !=
        config.services.ip-mesh.self) config.services.ip-mesh.peers);
      networks = lib.mapAttrs' (name: address: {
        name = "50-${name}-tnl";
        value = {
          name = "${name}-tnl";
          linkConfig = {
            MTUBytes = "1302";
            RequiredForOnline = false;
          };
        };
      }) (lib.filterAttrs (name: _: name !=
        config.services.ip-mesh.self) config.services.ip-mesh.peers);
    };
  };
}
