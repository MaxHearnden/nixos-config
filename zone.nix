{ config, lib, pkgs, ... }:

let
  instanceModule = lib.types.submodule ({config, ...}: {
    options = {
      domain = lib.mkOption {
        description = "The domain to generate dnssec data for";
        type = lib.types.str;
        example = "dnssec.example";
      };
      ldns = lib.mkPackageOption pkgs "ldns" {
        pkgsText = "The ldns package used for key generation and signing";
      };
      signzoneArgs = lib.mkOption {
        description = "The arguments to pass to ldns-signzone";
        type = lib.types.separatedString " ";
      };
      ksks = lib.mkOption {
        description = "The name and algorithm of key signing keys to use";
        type = lib.types.attrsOf lib.types.str;
        example = {
          test-1 = "ed448";
          test-2 = "ecdsap384sha384";
        };
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
      zoneLifetime = lib.mkOption {
        description = "The time in seconds where the zone remains valid";
        type = lib.types.int;
        default = 60 * 60 * 24 * 30;
        defaultText = 60 * 60 * 24 * 30;
      };
      zskAlgorithms = lib.mkOption {
        description = "The algorithms to use when generating zone signing keys";
        type = lib.types.listOf lib.types.str;
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
    systemd = {
      services = lib.mapAttrs' (name: config: {
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
            RemainAfterExit = true;
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
            set -- ${lib.escapeShellArgs (lib.attrValues config.ksks)}
            for ksk in ${lib.escapeShellArgs (lib.attrNames config.ksks)}; do
              if ! [ -e "$STATE_DIRECTORY/$ksk/".private ] ||
                ! [ -e "$STATE_DIRECTORY/$ksk/".ds ] ||
                ! [ -e "$STATE_DIRECTORY/$ksk/".key ]; then
                mkdir -p "$STATE_DIRECTORY/$ksk"
                cd "$STATE_DIRECTORY/$ksk"
                ldns-keygen -a "$1" -k -s -f ${config.domain}
              fi
              shift
            done

            timestamp=$(date --utc +%s)
            expiary=$((timestamp + ${toString config.zoneLifetime}))

            cd "$(mktemp -d)"

            set --

            for algorithm in ${lib.escapeShellArgs config.zskAlgorithms}; do
              set -- "$@" "$(ldns-keygen -a "$algorithm" ${config.domain})"
            done

            ldns-signzone -f "/run/zone/${name}/zonefile" ${config.signzoneArgs} \
              -e "$expiary" \
              "${config.zoneFile}" "$@" ${lib.concatStringsSep " " (map (key:
              "\"$STATE_DIRECTORY\"/" + lib.escapeShellArg key + "/") (lib.attrNames
              config.ksks))}
          '';
        };
      }) config.services.zones;
      targets = lib.mapAttrs' (name: config: {
        name = "zone-${name}";
        value = {
          # Stop zone service
          conflicts = [ "zone-${name}.service" ];
          # Start zone service
          onSuccess = [ "zone-${name}.service" ];

          unitConfig.StopWhenUnneeded = true;
        };
      }) config.services.zones;
    };

    users = {
      users.zone = {
        isSystemUser = true;
        group = "zone";
      };
      groups.zone = {};
    };
  };
}
