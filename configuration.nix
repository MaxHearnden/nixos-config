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
        "net.ipv4.tcp_ecn" = 1;
      };
    };
    kernelPackages = pkgs.linuxPackages_latest;
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
    "zerotierone"
  ] ++ lib.optionals (config.networking.hostName == "max-nixos-pc") [
    "cuda_cccl"
    "cuda_cudart"
    "cuda_nvcc"
    "libcublas"
    "nvidia-settings"
    "nvidia-x11"
  ]);
  networking = {
    hosts = {
      "fc9c:6b89:ee1a:7a70:b542:0000:0000:0001" = ["max-nixos-chromebooksd2-zerotier-6plane" "max-nixos-chromebooksd2-zerotier-ipv6" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "fd80:56c2:e21c:3d4b:0c99:931a:7a70:b542" = ["max-nixos-chromebooksd2-zerotier-rfc4193" "max-nixos-chromebooksd2-zerotier-ipv6" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "172.28.156.146" = ["max-nixos-chromebooksd2-zerotier-ipv4" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "fc9c:6b89:ee8e:d99a:c753:0000:0000:0001" = ["max-nixos-laptop-zerotier-6plane" "max-nixos-laptop-zerotier-ipv6" "max-nixos-laptop-zerotier" "max-nixos-laptop"];
      "fd80:56c2:e21c:3d4b:0c99:938e:d99a:c753" = ["max-nixos-laptop-zerotier-rfc4193" "max-nixos-laptop-zerotier-ipv6" "max-nixos-laptop-zerotier" "max-nixos-laptop"];
      "172.28.84.43" = ["max-nixos-laptop-zerotier-ipv4" "max-nixos-laptop-zerotier" "max-nixos-laptop"];
      "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258" = ["max-nixos-workstation-zerotier-rfc4193" "max-nixos-workstation-zerotier-ipv6" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      "fc9c:6b89:eec5:0d88:e258:0000:0000:0001" = ["max-nixos-workstation-zerotier-6plane" "max-nixos-workstation-zerotier-ipv6" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      "172.28.10.244" = ["max-nixos-workstation-zerotier-ipv4" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      "fd80:56c2:e21c:3d4b:0c99:93ba:b3a3:f197" = ["max-nixos-dell-zerotier-rfc4193" "max-nixos-dell-zerotier-ipv6" "max-nixos-dell-zerotier" "max-nixos-dell"];
      "fc9c:6b89:eeba:b3a3:f197:0000:0000:0001" = ["max-nixos-dell-zerotier-6plane" "max-nixos-dell-zerotier-ipv6" "max-nixos-dell-zerotier" "max-nixos-dell"];
      "172.28.12.138" = ["max-nixos-dell-zerotier-ipv4" "max-nixos-dell-zerotier" "max-nixos-dell"];
      "fd80:56c2:e21c:3d4b:0c99:93d9:c2b9:c567" = ["max-nixos-pc-zerotier-rfc4193" "max-nixos-pc-zerotier-ipv6" "max-nixos-pc-zerotier" "max-nixos-pc"];
      "fc9c:6b89:eed9:c2b9:c567:0000:0000:0001" = ["max-nixos-pc-zerotier-6plane" "max-nixos-pc-zerotier-ipv6" "max-nixos-pc-zerotier" "max-nixos-pc"];
      "172.28.13.156" = ["max-nixos-pc-zerotier-ipv4" "max-nixos-pc-zerotier" "max-nixos-pc"];
      "fd80:56c2:e21c:3d4b:0c99:9345:d31f:06d6" = ["max-guix-dell-zerotier-rfc4193" "max-guix-dell-zerotier-ipv6" "max-guix-dell-zerotier" "max-guix-dell"];
      "fc9c:6b89:ee45:d31f:06d6:0000:0000:0001" = ["max-guix-dell-zerotier-6plane" "max-guix-dell-zerotier-ipv6" "max-guix-dell-zerotier" "max-guix-dell"];
      "172.28.128.58" = ["max-guix-dell"];
    };
    firewall = {
      interfaces = {
        ztmjfp7kiq = {
          allowedTCPPorts = [
            22 # ssh
          ];
        };
      };
    };
    nftables = {
      enable = true;
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

        "network.trr.custom_uri" = "https://9.9.9.9/dns-query";
        "network.trr.mode" = 3;
        "network.trr.uri" = "https://9.9.9.9/dns-query";
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
    ssh.extraConfig = ''
      VerifyHostKeyDNS yes
    '';
    steam = {
      enable = true;
    };
    wireshark = {
      enable = true;
    };
  };
  security = {
    doas.enable = true;
    sudo.enable = false;
  };
  services = {
    avahi = {
      enable =
        lib.mkIf (config.networking.hostName != "max-nixos-workstation" ||
        config.networking.hostName != "max-nixos-pc") false;
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
    openssh = {
      openFirewall = false;
      settings = {
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
      packages = [
        pkgs.oversteer
      ];
    };
    unbound = {
      enable = true;
      # Pc is on an unblocked network
      settings = lib.mkMerge [
        (lib.mkIf (config.networking.hostName != "max-nixos-pc" &&
        config.networking.hostName != "max-nixos-workstation") {
          server = {
            qname-minimisation = false;
            tls-use-sni = false;
          };
          forward-zone = {
            name = ".";
            forward-addr = ["9.9.9.9#dns.quad9.net" "149.112.112.112#dns.quad9.net" "2620:fe::fe#dns.quad9.net" "2620:fe::9#dns.quad9.net"];
            forward-tls-upstream = true;
          };
        })
        {
          server = {
            do-not-query-localhost = false;
            domain-insecure = ["test."];
            ede = true;
            local-zone = [
              "home.arpa. nodefault"
              "test. nodefault"
            ];
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
              "zandoodle.me.uk"
            ];
            trust-anchor-file = "/etc/dnssec-trust-anchors.d/home.positive";
          };
          stub-zone = [
            {
              name = "test.";
              stub-addr = [
                "::1@8053"
              ];
            }
          ];
        }
      ];
    };
    xserver = {
      desktopManager = {
        gnome = {
          enable = true;
        };
        xterm = {
          enable = true;
        };
      };
      displayManager = {
        gdm = {
          enable = true;
        };
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
    zerotierone = {
      enable = true;
      joinNetworks = [ "8056c2e21c3d4b0c" ];
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
          RestrictNetworkInterfaces = "~tailscale0";
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallErrorNumber = "ENOSYS";
          SystemCallFilter = [ "@debug @system-service @mount @sandbox sethostname setdomainname" ];
          SystemCallLog = "~@system-service @mount @sandbox sethostname setdomainname";
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

      # Disable rpc units requiring krb5
      rpc-gssd = {
        enable = false;
      };
      rpc-svcgssd = {
        enable = false;
      };
      tailscaled = {
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
          RestrictNetworkInterfaces = "~ztmjfp7kiq";
          Environment = [ "TS_DEBUG_FIREWALL_MODE=nftables" "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket" ];
        };
        wants = [ "modprobe@tun.service" ];
        after = [ "modprobe@tun.service" ];
        confinement = {
          enable = true;
          packages = [ pkgs.tailscale ];
        };
      };
      zerotierone = {
        serviceConfig = {
          UMask = "0077";
          BindPaths = "/var/lib/zerotier-one /dev/net/tun";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /etc/static/ssl";
          DeviceAllow = "/dev/net/tun";
          AmbientCapabilities = "CAP_NET_ADMIN";
          ProtectKernelModules = true;
          ProtectProc = [ "invisible" ];
          SystemCallFilter = [ "@system-service" "~@privileged" ];
          PrivateUsers = lib.mkForce false;
          NoNewPrivileges = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          ProtectHostname = true;
          LockPersonality = true;
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectSystem = lib.mkForce "strict";
          SystemCallArchitectures = "native";
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          ProtectHome = true;
          CapabilityBoundingSet = "CAP_NET_ADMIN";
          ProcSubset = "pid";
          ExecStart = lib.mkForce "${config.services.zerotierone.package}/bin/zerotier-one -p${toString config.services.zerotierone.port} -U";
          ExecStartPre = lib.mkForce [];
          User = "zerotierd";
          Group = "zerotierd";
          RemoveIPC = true;
          RestrictNetworkInterfaces = "~tailscale0";
        };
        wants = [ "modprobe@tun.service" ];
        after = [ "modprobe@tun.service" ];
        confinement = {
          enable = true;
          fullUnit = true;
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
        "d /var/lib/zerotier-one 700 zerotierd zerotierd"
        "Z /var/lib/zerotier-one - zerotierd zerotierd"
        "d /var/lib/zerotier-one/networks.p 700 zerotierd zerotierd"
        "v /home/max/build 755 max users"
        "d /nix/var/nix/builds 755 root root 7d"
      ] ++ map (netId: "f /var/lib/zerotier-one/networks.p/${netId}.conf 700 zerotierd zerotierd") config.services.zerotierone.joinNetworks;
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
      zerotierd = {
        isSystemUser = true;
        group = "zerotierd";
      };
    };
    groups = {
      nix-gc = {};
      sh = {};
      tailscale = {};
      vfio = {};
      zerotierd = {};
    };
    users = {
      max = {
        extraGroups = [ "wheel" "dialout" "networkmanager" "plugdev" "video" "wireshark" "tss" ];
        isNormalUser = true;
        packages = with pkgs; [
          authenticator
          btop
          cargo-watch
          comma
          devcontainer
          dig
          discord
          dnsmasq
          dwarf-fortress
          elinks
          emacs
          espup
          ethtool
          file
          firmware-manager
          gcc
          gdb
          ghex
          gnome-tweaks
          graphviz
          gtkterm
          headsetcontrol
          htop
          inputs.nixos-kexec.packages.x86_64-linux.default
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.minimal-bootstrap.mescc-tools
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.snis
          keepassxc
          ldns
          ldns.examples
          libreoffice-fresh
          linux-manual
          lshw
          lsof
          man-pages-posix
          (man-pages.overrideAttrs (
            { patches ? [], ... }: {
              patches = patches ++ [ ./fs-manpages.patch ];
            }))
          mixxx
          nix-du
          nmap
          nodejs
          notepadqq
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
          plover.dev
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
          signal-desktop
          simutrans
          slirp4netns
          sshfs
          tea
          teams-for-linux
          texliveFull
          tpm2-tools
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
                inherit (exts.erlang-ls) erlang-ls;
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
            OLLAMA_HOST=172.28.13.156:11434 exec ${lib.getExe ollama} "$@"
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
