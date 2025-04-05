{ config, lib, pkgs, ... }:

let
  instanceModule = lib.types.submodule ({config, ...}: {
    options = {
      domain = lib.mkOption {
        description = "The domain to generate dnssec data for";
        type = lib.types.str;
        example = "dnssec.test";
      };
      ldns = lib.mkPackageOption pkgs "ldns" {
        pkgsText = "The ldns package used for key generation and signing";
      };
      zone = lib.mkOption {
        description = "zone data";
        type = lib.types.lines;
      };
      zoneFile = lib.mkOption {
        description = "The path to the zone file to sign";
        type = lib.types.path;
        default = pkgs.writeText "zonefile" config.zone;
        defaultText = lib.literalExpression
          "pkgs.writeText \"zonefile\" config.zone";
      };
      signzoneArgs = lib.mkOption {
        description = "The arguments to pass to ldns-signzone";
        type = lib.types.separatedString " ";
      };
      ksks = lib.mkOption {
        description = "The name of key signing keys to use";
        type = lib.types.listOf lib.types.str;
      };
      algorithm = lib.mkOption {
        description = "The algorithm to use when generating keys";
        type = lib.types.str;
      };
    };
  });

in {
  options.services.zones = lib.mkOption {
    description = "dnssec signed zones";
    type = lib.types.attrsOf instanceModule;
    default = {};
  };

  config = lib.mkIf (config.services.zones != {}) {
    systemd.services = lib.mapAttrs' (name: config: {
      name = "zone-${name}";
      value = {
        confinement = {
          enable = true;
          packages = [ pkgs.coreutils config.ldns.examples ];
        };
        serviceConfig = {
          CapabilityBoundingSet = "";
          Group = "zone";
          IPAddressDeny = "any";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          RestrictAddressFamilies = "none";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RuntimeDirectory = "zone/${name}";
          RuntimeDirectoryPreserve = true;
          StateDirectory = "zone/${name}";
          StateDirectoryMode = "755";
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged @resources"];
          User = "zone";
        };
        path = [ config.ldns.examples ];
        script = ''
          set -x
          for ksk in ${lib.escapeShellArgs config.ksks}; do
            if ! [ -e "$STATE_DIRECTORY/$ksk/".private ] ||
              ! [ -e "$STATE_DIRECTORY/$ksk/".ds ] ||
              ! [ -e "$STATE_DIRECTORY/$ksk/".key ]; then
              mkdir -p "$STATE_DIRECTORY/$ksk"
              cd "$STATE_DIRECTORY/$ksk"
              ldns-keygen -a ${config.algorithm} -k -s -f ${config.domain}
            fi
          done

          cd "$(mktemp -d)"

          zsk=$(ldns-keygen -a ${config.algorithm} ${config.domain})

          ldns-signzone -f "/run/zone/${name}/zonefile" ${config.signzoneArgs} \
            ${config.zoneFile} "$zsk" ${lib.concatStringsSep " " (map (key:
            "$STATE_DIRECTORY/" + lib.escapeShellArg key + "/") config.ksks)}
        '';
      };
    }) config.services.zones;

    users = {
      users.zone = {
        isSystemUser = true;
        group = "zone";
      };
      groups.zone = {};
    };
  };
}
