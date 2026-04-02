{ config, lib, pkgs, ... }:

let
  inherit (lib) types;
  cfg = config.services.bird-cfg;
  fileModule = types.submodule ({config, name, ...}: {
    options = {
      text = lib.mkOption {
        type = types.str;
      };
      source = lib.mkOption {
        default = pkgs.writeText "${name}.conf" config.text;
        type = types.path;
      };
    };
  });
in

{
  options.services.bird-cfg = {
    enable = lib.mkEnableOption "bird.d configuration";
    files = lib.mkOption {
      type = types.attrsOf fileModule;
    };
    configDir = lib.mkOption {
      type = types.path;
    };
  };
  config = {
    environment.etc."bird.d".source = cfg.configDir;
    entworking.firewall.tailscale0.allowedTCPPorts = [ 8000 ];
    services = {
      bird.config = "include \"${cfg.configDir}/*.conf\";";
      bird-cfg.configDir = pkgs.linkFarm "bird.d" (
        lib.mapAttrs' (name: file:
          {
            name = "${name}.conf";
            value = file.source;
          }) cfg.files);
      bird-lg.proxy = {
        enable = true;
        listenAddresses = [ "[::]:8000" ];
      };
    };
  };
}
