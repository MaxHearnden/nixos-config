# Global configuration

{ config, pkgs, inputs, lib, ... }:

{
  imports = [ ./pcrlock.nix ];
  boot = {
    binfmt = {
      emulatedSystems = [
        "armv7l-linux"
        "aarch64-linux"
        "mips-linux"
        "mipsel-linux"
        "mips64-linux"
        "mips64el-linux"
        "riscv32-linux"
        "riscv64-linux"
      ];
    };
    initrd = {
      systemd = {
        enable = true;
      };
    };
    kernel = {
      sysctl = {
        "net.core.fb_tunnels_only_for_init_net" = 2;
        "net.ipv4.tcp_ecn" = 1;
        "net.ipv4.tcp_fastopen" = 3;
      };
    };
    kernelPackages = pkgs.linuxPackages_latest;
    kernelPatches = [
      {
        name = "krb5-aes-sha2";
        structuredExtraConfig.RPCSEC_GSS_KRB5_ENCTYPES_AES_SHA2 = lib.kernel.yes;
        patch = null;
      }
    ];
    loader = {
      efi = {
        canTouchEfiVariables = true;
        efiSysMountPoint = "/boot";
      };
    };
  };
  console = {
    keyMap = "uk";
  };
  documentation = {
    dev = {
      enable = true;
    };
  };
  environment = {
    etc = {
      "dnssec-trust-anchors.d/home.positive".text = ''
        max.home.arpa. IN DS 6286 16 2 e5d985578b9746bfe1c6ff47e87e27f9be9942bf947c7ae18c448c86c303db0e
        max.home.arpa. IN DS 5629 14 4 663b18a6e58159ea67190937115450b87c60222a4f8d13395acf3b091cf6155e4be365d636452e9427c7818866be9d65
      '';
      "home.bind.keys".text = ''
        trust-anchors {
          max.home.arpa. initial-ds 6286 16 2 "e5d985578b9746bfe1c6ff47e87e27f9be9942bf947c7ae18c448c86c303db0e";
          max.home.arpa. initial-ds 5629 14 4 "663b18a6e58159ea67190937115450b87c60222a4f8d13395acf3b091cf6155e4be365d636452e9427c7818866be9d65";
        };
      '';
      "xdg/neomutt/neomuttrc".text = ''
        source ${pkgs.neomutt}/etc/neomuttrc
        set imap_user = max@zandoodle.me.uk
        set imap_pass = `op read -n op://Private/5lnrtyp6srjblkeczdaipaltxa/password`
        set spool_file = imaps://max@zandoodle.me.uk@imap.zandoodle.me.uk
        set imap_check_subscribed = yes
        set edit_headers = yes
        set smtp_url = smtps://max@zandoodle.me.uk@smtp.zandoodle.me.uk
        set imap_pass = `op read -n op://Private/5lnrtyp6srjblkeczdaipaltxa/password`
        set smtp_pass = `op read -n op://Private/5lnrtyp6srjblkeczdaipaltxa/password`

        set header_cache = ~/.cache/neomutt/cache/
        set message_cachedir = ~/.cache/neomutt/cache/

        set header_cache_compress_method = "zstd"
        set header_cache_compress_level = 3

        set tmpdir = /run/user/1000

        set from = max@zandoodle.me.uk
        set use_threads = yes
        set pager_index_lines = 6
        set pager_context = 3
        set pager_stop = yes
        set editor = "nvim"
        set reply_with_xorig = yes
        alternates 'zandoodle.me.uk$'
        alternates 'compsoc-dev.com$'

        set reverse_name = yes
        set use_from = yes
        set from = "max@zandoodle.me.uk"

        bind index G imap-fetch-mail
        set move = yes
        set mbox_type = "maildir"
        set keep_flagged = yes
        set record = imaps://max@zandoodle.me.uk@imap.zandoodle.me.uk/Sent
        set auto_edit = yes
        set fast_reply = yes
        unignore Authentication-Results
      '';
    };
    sessionVariables.SYSTEMD_EDITOR = "nvim";
    shellAliases = {
      sda = "systemd-analyze security --no-pager";
      rpush = "git pull --rebase && git push";
      as-btrbk = "doas setpriv --ambient-caps +dac_read_search,+chown,+fsetid,+setfcap,+sys_admin,+fowner,+dac_override --inh-caps +dac_read_search,+chown,+fsetid,+setfcap,+sys_admin,+fowner,+dac_override --reuid btrbk --init-groups";
    };
  };
  fileSystems = {
    "/" = {
      options = [ "noatime" "user_subvol_rm_allowed" "nosuid" "nodev" "compress=zstd" "subvol=/@NixOS" "defaults" ];
    };
    "/nexus" =
      let root = config.fileSystems."/";
      in {
        inherit (root) device fsType;
        options = (lib.filter (option: !lib.hasPrefix "subvol=" option) root.options) ++ [ "subvol=/" ];
      };
    "/nix" =
      let root = config.fileSystems."/";
      in {
        inherit (root) device fsType;
        options = (lib.filter (option: !lib.hasPrefix "subvol=" option) root.options) ++ [ "subvol=/nix" ];
      };
    "/boot" = {
      options = [
        "umask=0077"
        "nosuid"
        "nodev"
        "noatime"
        "noexec"
        "x-systemd.automount"
        "x-systemd.idle-timeout=10s"
      ];
    };
    "/home/max/h-drive" = {
      enable = false;
      device = "//homes.lancs.ac.uk/04/hearndem";
      fsType = "cifs";
      options = [
        "defaults"
        "uid=max"
        "gid=users"
        "cred=/root/lancaster-creds"
        "mfsymlinks"
        "file_mode=0700"
        "dir_mode=0700"
        "nofail"
        "x-systemd.automount"
        "x-systemd.idle-timeout=5m"
      ];
    };
  };
  hardware = {
    bluetooth = {
      disabledPlugins = ["input"];
    };
    enableRedistributableFirmware = true;
  };
  i18n = {
    inputMethod = {
      enable = true;
      fcitx5.waylandFrontend = true;
      type = "fcitx5";
    };
    defaultLocale = "en_GB.UTF-8";
  };
  nix = {
    daemonIOSchedClass = "idle";
    daemonCPUSchedPolicy = "idle";
    gc = {
      automatic = true;
      options = "-d";
      persistent = true;
    };
    nixPath = [ "nixpkgs=${inputs.nixpkgs-unstable}" "nixos=${inputs.nixpkgs}" ];
    registry = lib.mapAttrs (_: flake: {
      inherit flake;
    }) inputs;
    settings = {
      allowed-users = [ "max" "nix-gc" ];
      auto-optimise-store = true;
      build-dir = "/nix/var/nix/builds";
      experimental-features = [
        "ca-derivations"
        "cgroups"
        "flakes"
        "nix-command"
      ];
      flake-registry = null;
      store = "daemon";
      use-cgroups = true;
    };
  };
  nixpkgs.config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) ([
    "1password"
    "1password-cli"
    "discord"
    "dwarf-fortress"
    "steam"
    "steam-unwrapped"
  ] ++ lib.optionals (builtins.elem config.networking.hostName [ "max-nixos-pc"
  "max-nixos-laptop"]) [
    "cuda_cccl"
    "cuda_cudart"
    "cuda_nvcc"
    "libcublas"
    "nvidia-settings"
    "nvidia-x11"
  ]);
  networking = {
    firewall = {
      allowedUDPPorts = [
        41641 # Tailscale
      ];
      interfaces.tailscale0.allowedTCPPorts = [
        22
      ];
    };
    nftables = {
      enable = true;
      tables.tailscale-enforcement = {
        family = "inet";
        content = ''
          chain output {
            type filter hook output priority filter - 10;
            oiftype {768, 769, 776} udp dport 41641 drop
            oifname { plat, tayga } udp dport 41641 drop
          }
        '';
      };
    };
  };
  programs = {
    _1password = {
      enable = true;
    };
    _1password-gui = {
      enable = true;
    };
    command-not-found = {
      enable = false;
    };
    firefox = {
      enable = true;
      preferences = {
        # Block hateful content
        "network.dns.localDomains" = "www.phoronix.com,phoronix.com";

      } // lib.optionalAttrs (config.networking.hostName != "max-nixos-pc") {
        "network.trr.custom_uri" = "https://local-tailscale.zandoodle.me.uk/dns-query";
        "network.trr.mode" = 3;
        "network.trr.uri" = "https://local-tailscale.zandoodle.me.uk/dns-query";
      };
    };
    fish = {
      enable = true;
      interactiveShellInit = ''
        ${config.systemd.package}/bin/systemctl shutdown --quiet --when=show
        begin
          if ! set -l system_status "$(${config.systemd.package}/bin/systemctl \
              is-system-running)"
            echo The system status is currently "$system_status"
          end
        end
      '';
    };
    git = {
      enable = true;
      package = pkgs.gitFull;
      config = {
        core = {
          excludesFile = pkgs.writeText "gitignore" ''
            .virtfs_metadata
          '';
        };
        user = {
          email = "maxoscarhearnden@gmail.com";
          name = "MaxHearnden";
        };
      };
    };
    java = {
      binfmt = true;
      enable = true;
    };
    neovim = {
      configure = {
        customRC = ''
          set mouse=a
          set shiftwidth=2
          set expandtab
          set colorcolumn=80
          set textwidth=80
          inoremap {<CR> {<CR>}<Esc>ko
          inoremap [<CR> [<CR>]<Esc>ko
          inoremap (<CR> (<CR>)<Esc>ko
        '';
        packages = {
          haskell = with pkgs.vimPlugins; {
            start = [ nvim-lspconfig ];
          };
          nix = with pkgs.vimPlugins; {
            start = [ vim-nix ];
          };
        };
      };
      defaultEditor = true;
      enable = true;
      withNodeJs = true;
    };
    nix-index = {
      enable = true;
    };
    ssh = {
      extraConfig = ''
        VerifyHostKeyDNS yes
        Host *.zandoodle.me.uk zandoodle.me.uk
        StrictHostKeyChecking yes
        UserKnownHostsFile /dev/null
        GSSAPIAuthentication yes

        Host localhost
        CanonicalizeHostname no

        Host *
        CanonicalDomains zandoodle.me.uk int.zandoodle.me.uk
        CanonicalizeFallbackLocal no
        CanonicalizeHostname yes
        CanonicalizeMaxDots 0
      '';
      package = pkgs.opensshWithKerberos;
    };
    steam = {
      enable = true;
    };
    wireshark = {
      enable = true;
    };
  };
  security = {
    doas.enable = true;
    krb5 = {
      enable = true;
      settings = {
        libdefaults = {
          default_ccache_name = "DIR:/run/user/%{uid}";
          default_realm = "WORKSTATION.ZANDOODLE.ME.UK";
          dns_canonicalize_hostname = "fallback";
          dns_lookup_realm = true;
          permitted_enctypes = "aes256-sha2";
          spake_preauth_groups = "edwards25519";
          rdns = false;
        };
        realms = {
          "ZANDOODLE.ME.UK" = {
            disable_encrypted_timestamp = true;
            admin_server = "local.zandoodle.me.uk";
          } // lib.optionalAttrs (config.networking.hostName != "max-nixos-pc") {
            sitename = "tailscale";
          };
          "WORKSTATION.ZANDOODLE.ME.UK" = {
            disable_encrypted_timestamp = true;
            admin_server = "workstation.zandoodle.me.uk";
          };
        };
      };
    };
    pam.krb5.enable = false;
    sudo.enable = false;
  };
  services = {
    avahi = {
      enable = lib.mkIf (config.networking.hostName != "max-nixos-pc") false;
      nssmdns6 = true;
    };
    btrbk = {
      instances = {
        btrbk = {
          settings = {
            backend = "btrfs-progs";
            target_preserve_min = "7d";
            target_preserve = "14d 6w 6m";
            ssh_user = "btrbk";
            send_compressed_data = "yes";
            stream_buffer = "25%";
            stream_compress = "zstd";
            snapshot_preserve = "14d 3m";
            snapshot_preserve_min = "2d";
            snapshot_dir = "snapshots/btrbk";
            transaction_syslog = "user";
            volume = {
              "/nexus" = {
                subvolume = "@NixOS";
              };
            };
          };
          onCalendar = "daily UTC";
        };
      };
    };
    desktopManager.gnome.enable = true;
    displayManager.gdm.enable = true;
    fwupd = {
      enable = true;
    };
    gnome = {
      core-developer-tools = {
        enable = true;
      };
      games = {
        enable = true;
      };
    };
    libinput = {
      enable = true;
    };
    nfs.idmapd.settings.General.Domain = "workstation.zandoodle.me.uk";
    openssh = {
      openFirewall = false;
      settings = {
        GSSAPIAuthentication = true;
        GSSAPIStrictAcceptorCheck = false;
        X11Forwarding = true;
      };
    };
    pulseaudio = {
      extraConfig = ''
        .nofail
        unload-module module-suspend-on-idle
        .fail
      '';
    };
    resolved.enable = false;
    sshd = {
      enable = true;
    };
    tailscale = {
      enable = true;
    };
    udev = {
      extraRules = ''
        KERNEL=="uinput", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"
      '';
      packages = [
        pkgs.oversteer
      ];
    };
    unbound = {
      enable = true;
      enableRootTrustAnchor = false;
      package = pkgs.unbound-full;
      # Pc is on an unblocked network
      settings = {
        server = {
          auto-trust-anchor-file = "/var/lib/unbound/root.key";
          dns64-prefix = "fd09:a389:7c1e:3::/64";
          dns64-ignore-aaaa = "vodafone.broadband";
          do-not-query-localhost = false;
          domain-insecure = ["test."];
          ede = true;
          local-zone = [
            "home.arpa. nodefault"
            "test. nodefault"
          ];
          module-config = "\"respip dns64 validator iterator\"";
          private-address = [
            "10.0.0.0/8"
            "100.64.0.0/10"
            "127.0.0.0/8"
            "169.254.0.0/16"
            "172.16.0.0/12"
            "192.168.0.0/16"
            "::ffff:10.0.0.0/104"
            "::ffff:100.64.0.0/106"
            "::ffff:127.0.0.0/104"
            "::ffff:169.254.0.0/112"
            "::ffff:172.16.0.0/108"
            "::ffff:192.168.0.0/112"
            "::1/128"
            "fc00::/7"
            "fe80::/10"
          ];
          private-domain = [
            "broadband"
            "compsoc-dev.com"
            "home.arpa"
            "test"
            "zandoodle.me.uk"
          ];
          qname-minimisation = config.networking.hostName == "max-nixos-pc";
          response-ip = [
            "fd09:a389:7c1e:3::/64 redirect"
            "fd09:a389:7c1e:3:c0:0:aa00::/103 always_transparent"
            "fd09:a389:7c1e:3:c0:a800::/88 always_transparent"
          ];
          trust-anchor-file = "/etc/dnssec-trust-anchors.d/home.positive";
          val-log-level = 2;
        };
        forward-zone = [
          {
            name = ".";
            forward-addr =
              "fd7a:115c:a1e0::1a01:5208#local-tailscale.zandoodle.me.uk";
            forward-first = config.networking.hostName == "max-nixos-pc";
            forward-tls-upstream = true;
          }
        ];
        stub-zone = [
          {
            name = "test.";
            stub-addr = [
              "::1@8053"
            ];
          }
        ];
      };
    };
    xserver = {
      desktopManager = {
        xterm = {
          enable = true;
        };
      };
      displayManager = {
        startx = {
          enable = true;
        };
      };
      enable = true;
      windowManager = {
        i3 = {
          enable = true;
        };
        xmonad = {
          enable = true;
        };
      };
      xkb = {
        layout = "gb";
      };
    };
  };
  specialisation.nox.configuration = {
    boot = {
      kernelParams = [
        "systemd.unit=multi-user.target"
      ];
    };
  };
  system = {
    configurationRevision = inputs.self.rev or "dirty";
    stateVersion = "25.05";
  };
  systemd = {
    additionalUpstreamSystemUnits = [
      "soft-reboot.target"
      "systemd-soft-reboot.service"
    ];
    services = {
      "btrbk-btrbk" = {
        restartIfChanged = false;
        confinement = {
          enable = true;
        };
        serviceConfig = {
          BindPaths = ["/nexus"];
          BindReadOnlyPaths = ["/dev/log /run/systemd/journal/socket /run/systemd/journal/stdout ${config.environment.etc."btrbk/btrbk.conf".source}:/etc/btrbk/btrbk.conf /etc/passwd /etc/hosts"];
          PrivateUsers = lib.mkForce false;
          RestrictNamespaces = true;
          UMask = "0077";
          SystemCallFilter = [ "@system-service" "~@resources" ];
          ProtectClock = true;
          ProtectKernelLogs = true;
          MemoryDenyWriteExecute = true;
          CapabilityBoundingSet = [ "CAP_SYS_ADMIN CAP_FOWNER CAP_DAC_OVERRIDE" ];
          AmbientCapabilities = [ "CAP_SYS_ADMIN CAP_FOWNER CAP_DAC_OVERRIDE" ];
          SystemCallArchitectures = "native";
          ProtectHome = true;
          NoNewPrivileges = true;
          RemoveIPC = true;
          ProtectHostname = true;
          LockPersonality = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictRealtime = true;
          IPAddressDeny = "any";
          StateDirectoryMode = "0700";
        };
      };
      nix-gc = {
        serviceConfig = {
          BindReadOnlyPaths = "/nix/var/nix/daemon-socket";
          BindPaths = "/nix/var/nix/profiles";
          User = "nix-gc";
          Group = "nix-gc";
          NoNewPrivileges = true;
          RestrictAddressFamilies = "AF_UNIX";
          RestrictNamespaces = true;
          UMask = "0077";
          SystemCallFilter = [ "@system-service" "~@resources @privileged" ];
          SystemCallArchitectures = "native";
          ProtectClock = true;
          ProtectKernelLogs = true;
          MemoryDenyWriteExecute = true;
          CapabilityBoundingSet = "";
          RemoveIPC = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictRealtime = true;
          PrivateNetwork = true;
          IPAddressDeny = "any";
          StateDirectory = "nix-gc";
          StateDirectoryMode = "0700";
        };
        confinement = {
          enable = true;
        };
        environment = {
          XDG_STATE_HOME = "%S/nix-gc";
        };
      };
      nix-daemon = {
        serviceConfig = {
          BindPaths = "/dev/kvm";
          CacheDirectory = "nix";
          CacheDirectoryMode = "0700";
          CapabilityBoundingSet = "CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER CAP_SYS_PTRACE";
          DeviceAllow = "/dev/kvm";
          ExecStart = [
            ""
            "@${lib.getExe' config.nix.package "nix-daemon"} nix-daemon --daemon --option store local"
          ];
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectHome = "read-only";
          ProtectKernelModules = true;
          ProtectSystem = "strict";
          ReadWritePaths = "/nix /tmp";
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          RestrictNamespaces = "user net mnt ipc pid uts cgroup";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallErrorNumber = "ENOSYS";
          SystemCallFilter = [ "@debug @system-service @mount @sandbox sethostname setdomainname bpf" ];
        };
        environment.XDG_CACHE_HOME = "%C";
      };
      nscd = {
        serviceConfig = {
          CapabilityBoundingSet = "";
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          LockPersonality = true;
          ProtectHostname = true;
          ProtectClock = true;
          SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          RestrictNamespaces = true;
          ProtectKernelTunables = true;
          RestrictRealtime = true;
        };
      };
      podman = {
        enable = false;
      };

      tailscaled = {
        environment = {
          DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket";
          TS_DEBUG_FIREWALL_MODE = "nftables";
          TS_DEBUG_MTU = "1350";
        };
        serviceConfig = {
          UMask = "0077";
          BindPaths = "/dev/net/tun";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /etc/static/ssl /run/dbus/system_bus_socket";
          User = "tailscale";
          Group = "tailscale";
          DeviceAllow = "/dev/net/tun";
          AmbientCapabilities = "CAP_NET_RAW CAP_NET_ADMIN";
          ProtectKernelModules = true;
          ProtectProc = [ "invisible" ];
          SystemCallFilter = [ "@system-service" "~@privileged" ];
          PrivateUsers = lib.mkForce false;
          RemoveIPC = true;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          ProtectSystem = lib.mkForce "strict";
          LockPersonality = true;
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          ProtectClock = true;
          ProtectKernelLogs = true;
          SystemCallArchitectures = "native";
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          ProtectHome = true;
          CapabilityBoundingSet = "CAP_NET_RAW CAP_NET_ADMIN";
        };
        wants = [ "modprobe@tun.service" ];
        after = [ "modprobe@tun.service" ];
        confinement = {
          enable = true;
          packages = [ config.services.tailscale.package ];
        };
      };
    };
    shutdownRamfs.enable = true;
    sockets = {
      podman = {
        enable = false;
      };
    };
    tmpfiles = {
      rules = [
        "d /nexus/snapshots/btrbk - btrbk btrbk"
        "A /nix/var/nix/profiles - - - - u:nix-gc:rwx,d:u:nix-gc:rwx,m::rwx,d:m::rwx"
        "v /home/max/build 755 max users"
        "d /nix/var/nix/builds 755 root root 7d"
      ];
      settings."10-trust-anchor"."/var/lib/unbound/root.key".C.argument =
        "${pkgs.dns-root-data}/root.key";
    };
    user = {
      services = {
        kodi-mount = {
          unitConfig = {
            ConditionUser = "max";
          };
          serviceConfig = {
            ExecStart = "${lib.getExe pkgs.sshfs} 192.168.1.80:/ %h/kodi -o reconnect -f";
            ExecStop = "/run/wrappers/bin/umount %h/kodi";
            Type = "exec";
          };
        };
      };
    };
  };
  time = {
    timeZone = "Europe/London";
  };
  users = {
    extraUsers = {
      nix-gc = {
        isSystemUser = true;
        group = "nix-gc";
      };
      sh = {
        description = "A user to allow for ~sh instead of ~/shared";
        group = "sh";
        home = "/home/max/shared";
        isSystemUser = true;
      };
      tailscale = {
        isSystemUser = true;
        group = "tailscale";
      };
    };
    groups = {
      nix-gc = {};
      sh = {};
      tailscale = {};
      vfio = {};
    };
    users = {
      max = {
        extraGroups = [
          "dialout"
          "input"
          "networkmanager"
          "plugdev"
          "tss"
          "video"
          "wheel"
          "wireshark"
        ];
        isNormalUser = true;
        packages = with pkgs; [
          alacritty
          authenticator
          blender
          btop
          bun
          cargo-watch
          comma
          devcontainer
          dig
          dino
          discord
          dnsmasq
          dwarf-fortress
          elinks
          emacs
          espup
          ethtool
          file
          file-roller
          firmware-manager
          gcc
          gdb
          ghex
          glslang
          gnome-tweaks
          godot
          godot-export-templates-bin
          graphviz
          gtkterm
          headsetcontrol
          htop
          inputs.nixos-kexec.packages.x86_64-linux.default
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.minimal-bootstrap.mescc-tools
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.snis
          inputs.plover-flake.packages.x86_64-linux.plover
          keepassxc
          ldns
          ldns.examples
          libreoffice-fresh
          lshw
          lsof
          man-pages-posix
          man-pages
          mixxx
          neomutt
          nix-du
          nmap
          nodejs
          ollama
          openssl
          oversteer
          p7zip
          passt
          pioneer
          pkgsCross.aarch64-multiplatform.buildPackages.gcc
          pkgsCross.aarch64-multiplatform.buildPackages.gdb
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gdb
          pkgsCross.riscv32.buildPackages.gcc
          pkgsCross.riscv32.buildPackages.gdb
          pkgsCross.riscv64.buildPackages.gcc
          pkgsCross.riscv64.buildPackages.gdb
          podman-compose
          powertop
          prismlauncher
          python3
          qemu
          qpdfview
          rare
          rdap
          rhythmbox
          ripgrep
          rustup
          shellcheck
          sidequest
          signal-desktop
          simutrans
          slang
          slirp4netns
          sshfs
          tea
          teams-for-linux
          texliveFull
          thunderbird
          tpm2-tools
          typst
          ungoogled-chromium
          usbutils
          vdrift
          vim
          vlc
          (vscode-with-extensions.override {
            vscode = vscodium;
            vscodeExtensions =
              let exts = inputs.vscode-extensions.extensions.${config.nixpkgs.system}.vscode-marketplace;
              in builtins.attrValues {
                inherit (exts.rust-lang) rust-analyzer;
                inherit (exts.haskell) haskell;
                inherit (exts.justusadam) language-haskell;
                inherit (exts.jnoortheen) nix-ide;
                inherit (exts.maelvalais) autoconf;
                inherit (exts.prince781) vala;
                inherit (exts.theumletteam) umlet;
              };
            })
          w3m
          wasistlos
          watchexec
          whois
          wineWowPackages.full
          winetricks
          wireshark
          wl-clipboard
          (writeShellScriptBin "ollama-pc" ''
            OLLAMA_HOST=https://pc.int.zandoodle.me.uk/ exec ${lib.getExe ollama} "$@"
          '')
          xclip
          xorg.xhost
          zgrviewer
        ];
        shell = pkgs.fish;
      };
    };
  };
  virtualisation = {
    podman = {
      enable = true;
    };
    vmVariant = {
      users = {
        users = {
          max = {
            password = "nixos";
          };
        };
      };
    };
  };
  zramSwap = {
    algorithm = "zstd";
    enable = true;
    memoryPercent = 100;
    priority = 5;
  };
}
