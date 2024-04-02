# Global configuration

{ config, pkgs, inputs, lib, ... }:

{
  imports = [ ./dev-environment.nix ];
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
    kernelPackages =
      let unstable-unfree = import inputs.nixpkgs-unstable {
        system = config.nixpkgs.system;
        config = config.nixpkgs.config;
      };
      in unstable-unfree.linuxKernel.packageAliases.linux_latest;
    kernelPatches = [
      {
        name = "Rust Support";
        patch = null;
        features = {
          rust = true;
        };
      }
    ];
    extraModulePackages = [
      # config.boot.kernelPackages.rtl8812au
      # config.boot.kernelPackages.rtl88x2bu
    ];
    initrd = {
      systemd = {
        enable = true;
      };
    };
    loader = {
      efi = {
        canTouchEfiVariables = true;
        efiSysMountPoint = "/boot/efi";
      };
      grub = {
        device = "nodev";
        efiSupport = true;
        enable = true;
        extraEntries = ''
          menuentry "iPXE" {
            chainloader @bootRoot@/ipxe.efi
          }

          menuentry "memtest86+" {
            chainloader @bootRoot@/memtest.efi
          }
        '';
        extraFiles = {
          "ipxe.efi" = "${pkgs.ipxe}/ipxe.efi";
          "memtest.efi" = "${pkgs.memtest86plus}/memtest.efi";
        };
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
    shellAliases = {
      sda = "systemd-analyze security --no-pager";
      rpush = "git pull --rebase && git push";
      as-btrbk = "sudo setpriv --ambient-caps +dac_read_search,+chown,+fsetid,+setfcap,+sys_admin,+fowner,+dac_override --inh-caps +dac_read_search,+chown,+fsetid,+setfcap,+sys_admin,+fowner,+dac_override --reuid btrbk --init-groups";
    };
  };
  fileSystems = {
    "/" = {
      options = [ "noatime" "user_subvol_rm_allowed" "nosuid" "nodev" ];
    };
    # "/home/max/h-drive" = {
    #   device = "//homes.lancs.ac.uk/04/hearndem";
    #   fsType = "cifs";
    #   options = [
    #     "defaults"
    #     "uid=max"
    #     "gid=users"
    #     "cred=/root/lancaster-creds"
    #     "mfsymlinks"
    #     "file_mode=0700"
    #     "dir_mode=0700"
    #     "nofail"
    #     "x-systemd.automount"
    #     "x-systemd.idle-timeout=5m"
    #   ];
    # };
  };
  hardware = {
    bluetooth = {
      disabledPlugins = ["input"];
    };
    enableAllFirmware = true;
    pulseaudio = {
      extraConfig = ''
        .nofail
        unload-module module-suspend-on-idle
        .fail
      '';
    };
  };
  i18n = {
    defaultLocale = "en_GB.utf8";
  };
  # krb5 = {
  #   domain_realm = {
  #     "172.28.10.244" = "WORKSTATION";
  #     "max-nixos-workstation" = "WORKSTATION";
  #   };
  #   enable = true;
  #   libdefaults = {
  #     default_realm = "WORKSTATION";
  #     ignore_acceptor_hostname = true;
  #   };
  #   realms = {
  #     WORKSTATION = {
  #       kdc = [
  #         "172.28.10.244"
  #       ];
  #     };
  #   };
  # };
  nix = {
    gc = {
      automatic = true;
      options = "-d";
      persistent = true;
    };
    nixPath = [ "nixpkgs=${inputs.nixpkgs-unstable}" "nixos=${inputs.nixpkgs}" ];
    package = pkgs.nix.overrideAttrs (
      {patches ? [], ...}: {
        patches = patches ++ [ ./8255.patch ];
      }
    );
    registry = lib.mapAttrs (_: flake: {
      inherit flake;
    }) inputs;
    settings = {
      auto-optimise-store = true;
      diff-hook = pkgs.diffoscope;
      experimental-features = [
        "nix-command"
        "flakes"
      ];
      trusted-public-keys = [ "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI=" "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ=" "cache.ngi0.nixos.org-1:KqH5CBLNSyX184S9BKZJo1LxrxJ9ltnY2uAs5c/f1MA=" ];
      trusted-substituters = [ "https://cache.ngi0.nixos.org" "https://cache.iog.io" ];
    };
  };
  nixpkgs = {
    config = {
      allowUnfree = true;
      segger-jlink = {
        acceptLicense = true;
      };
    };
  };
  networking = {
    hosts = {
      "fc9c:6b89:ee1a:7a70:b542:0000:0000:0001" = ["max-nixos-chromebooksd2-zerotier-6plane" "max-nixos-chromebooksd2-zerotier-ipv6" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "fd80:56c2:e21c:3d4b:0c99:931a:7a70:b542" = ["max-nixos-chromebooksd2-zerotier-rfc4193" "max-nixos-chromebooksd2-zerotier-ipv6" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "172.28.156.146" = ["max-nixos-chromebooksd2-zerotier-ipv4" "max-nixos-chromebooksd2-zerotier" "max-nixos-chromebooksd2"];
      "fd80:56c2:e21c:3d4b:0c99:93c5:0d88:e258" = ["max-nixos-workstation-zerotier-rfc4193" "max-nixos-workstation-zerotier-ipv6" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      "fc9c:6b89:eec5:0d88:e258:0000:0000:0001" = ["max-nixos-workstation-zerotier-6plane" "max-nixos-workstation-zerotier-ipv6" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      "172.28.10.244" = ["max-nixos-workstation-zerotier-ipv4" "max-nixos-workstation-zerotier" "max-nixos-workstation"];
      # "172.28.198.106" = ["max-nixos-laptop"];
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
      allowedTCPPorts = [
        # SimSig
        50505
        50507
        50509
      ];
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
    # adb = {
    #   enable = true;
    # };
    command-not-found = {
      enable = false;
    };
    fish = {
      enable = true;
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
      };
    };
    java = {
      binfmt = true;
      enable = true;
    };
    mininet = {
      enable = true;
    };
    neovim = {
      configure = {
        customRC = ''
          set mouse=a
          set shiftwidth=2
          set expandtab
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
    steam = {
      enable = true;
    };
    wireshark = {
      enable = true;
    };
  };
  security = {
    doas = {
      enable = true;
    };
    wrappers = {
      "mount.cifs" = {
        source = "${pkgs.cifs-utils}/bin/mount.cifs";
        owner = "root";
        group = "root";
        setuid = true;
      };
      "mount.nfs" = {
        source = "${pkgs.nfs-utils}/bin/mount.nfs";
        owner = "root";
        group = "root";
        setuid = true;
      };
    };
  };
  services = {
    avahi = {
      enable = false;
    };
    btrbk = {
      extraPackages = with pkgs; [
        zstd
      ];
      instances = {
        ${lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName} = {
          settings = {
            backend = "btrfs-progs";
            target_preserve_min = "no";
            target_preserve = "6w 6m";
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
        };
      };
    };
    cachefilesd = {
      enable = true;
    };
    dbus = {
      packages = [
        inputs.keyboard_mouse_emulate_on_raspberry.packages.x86_64-linux.default
      ];
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
    # guix = {
    #   enable = true;
    #   gc = {
    #     enable = true;
    #     extraArgs = [ "-d" ];
    #   };
    # };
    kmscon = {
      enable = true;
      extraOptions = "--xkb-layout gb";
    };
    openssh = {
      openFirewall = false;
      settings = {
        X11Forwarding = true;
      };
    };
    printing = {
      enable = true;
      drivers = [
        pkgs.cnijfilter2
      ];
    };
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
      layout = "gb";
      libinput = {
        enable = true;
      };
      windowManager = {
        i3 = {
          enable = true;
        };
        xmonad = {
          enable = true;
        };
      };
    };
    zerotierone = {
      enable = true;
      joinNetworks = [ "8056c2e21c3d4b0c" ];
    };
  };
  specialisation.nox.configuration = {
    services = {
      xserver = {
        autorun = false;
      };
    };
  };
  system = {
    extraDependencies = [
      # Prevent unnecicary gc and rebuild
      pkgs.pkgsCross.riscv32.buildPackages.gcc.info
      pkgs.pkgsCross.riscv64.buildPackages.gcc.info
    ];
    stateVersion = "23.05";
  };
  systemd = {
    services = let
      short-name = lib.substring 10 (lib.stringLength config.networking.hostName) config.networking.hostName;
    in {
      "btrbk-${short-name}" = {
        restartIfChanged = false;
        confinement = {
          enable = true;
        };
        serviceConfig = {
          BindPaths = ["/nexus"];
          BindReadOnlyPaths = ["/dev/log /run/systemd/journal/socket /run/systemd/journal/stdout ${config.environment.etc."btrbk/${short-name}.conf".source}:/etc/btrbk/${short-name}.conf /etc/passwd /etc/hosts"];
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
          ProtectHome = "tmpfs";
          NoNewPrivileges = true;
          RestrictAddressFamilies = "AF_UNIX";
          # SetLoginEnvironment = false;
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
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictRealtime = true;
          PrivateNetwork = true;
          IPAddressDeny = "any";
          # PrivateDevices = true;
        };
        confinement = {
          enable = true;
        };
        environment = {
          HOME = "/home/nix-gc";
        };
      };
      # wpa_supplicant = {
      #   serviceConfig = {
      #     RootDirectory = "/var/empty";
      #     TemporaryFileSystem = "/";
      #     SystemCallArchitectures = "native";
      #     NoNewPrivileges = true;
      #     PrivateMounts = true;
      #     MountAPIVFS = true;
      #     BindReadOnlyPaths = "/nix/store /run/dbus/system_bus_socket";
      #     RestrictNamespaces = true;
      #     CapabilityBoundingSet = "CAP_NET_ADMIN";
      #   };
      # };
      nix-daemon = {
        serviceConfig = {
          CapabilityBoundingSet = "CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER";
          ProtectSystem = "strict";
          BindPaths = "/dev/kvm";
          DeviceAllow = "/dev/kvm";
          # RootDirectory = "/var/empty";
          # TemporaryFileSystem = "/";
          # BindReadOnlyPaths = "/etc/nix /etc/resolv.conf /etc/ssl /etc/static/ssl /etc/passwd /etc/group /machines";
          # BindPaths = "/nix /root/.cache/nix /tmp";
          ReadWritePaths = "/nix /tmp";
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
          SystemCallFilter = [ "@system-service @mount @sandbox sethostname setdomainname @pkey" ];
          # PrivateMounts = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = "read-only";
          ProtectKernelModules = true;
          SocketBindDeny = "any";
          RestrictNamespaces = "user net mnt ipc pid uts";
          RestrictSUIDSGID = true;
          # IPAddressAllow = "172.28.10.244";
          RestrictNetworkInterfaces = "~tailscale0";
          # IPAddressDeny = "127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fd00::/8 169.254.0.0/16 fe80::/10 100.64.0.0/10";
          RestrictRealtime = true;
          CacheDirectory = "nix";
          CacheDirectoryMode = "0700";
          Environment = [ "XDG_CACHE_HOME=%C" ];
        };
      };
      # guix-daemon = {
      #   serviceConfig = {
      #     CapabilityBoundingSet = "CAP_SYS_CHROOT CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER";
      #     ProtectSystem = "strict";
      #     BindPaths = "/dev/kvm";
      #     DeviceAllow = "/dev/kvm";
      #     # RootDirectory = "/var/empty";
      #     # TemporaryFileSystem = "/";
      #     # BindReadOnlyPaths = "/etc/nix /etc/resolv.conf /etc/ssl /etc/static/ssl /etc/passwd /etc/group /machines";
      #     # BindPaths = "/nix /root/.cache/nix /tmp";
      #     ReadWritePaths = "/gnu /var/guix /tmp";
      #     RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
      #     SystemCallFilter = [ "@system-service @mount seccomp sethostname setdomainname @pkey" ];
      #     # PrivateMounts = true;
      #     NoNewPrivileges = true;
      #     LogsDirectory = "guix";
      #     PrivateDevices = true;
      #     ProtectClock = true;
      #     ProtectControlGroups = true;
      #     ProtectHome = "read-only";
      #     ProtectKernelModules = true;
      #     SocketBindDeny = "any";
      #     RestrictNamespaces = "user net mnt ipc pid uts";
      #     RestrictSUIDSGID = true;
      #     # IPAddressAllow = "172.28.10.244";
      #     RestrictNetworkInterfaces = "~tailscale0";
      #     # IPAddressDeny = "127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fd00::/8 169.254.0.0/16 fe80::/10 100.64.0.0/10";
      #     RestrictRealtime = true;
      #     CacheDirectory = "guix";
      #     CacheDirectoryMode = "0700";
      #     Environment = [ "XDG_CACHE_HOME=%C" ];
      #   };
      # };
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
      ovsdb = {
        serviceConfig = {
          User = "openvswitch";
          Group = "openvswitch";
          RuntimeDirectory = "openvswitch";
          RuntimeDirectoryPreserve = true;
          StateDirectory = "openvswitch";
          StateDirectoryMode = "0700";
          BindPaths = "%S/openvswitch:/var/db/openvswitch";
          AmbientCapabilities = "CAP_IPC_LOCK";
          UMask = "0027";
          PrivateTmp = true;
        };
      };
      ovs-vswitchd = {
        serviceConfig = {
          User = "openvswitch";
          Group = "openvswitch";
          RuntimeDirectory = "openvswitch";
          RuntimeDirectoryPreserve = true;
          AmbientCapabilities = "CAP_IPC_LOCK CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BROADCAST";
          CapabilityBoundingSet = "CAP_IPC_LOCK CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BROADCAST";
        };
      };
      tailscaled = {
        serviceConfig = {
          UMask = "0077";
          BindPaths = "/dev/net/tun";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /etc/static/ssl";
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
          Environment = [ "TS_DEBUG_FIREWALL_MODE=nftables" ];
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
    tmpfiles = {
      rules = [
        "d /nexus/snapshots/btrbk - btrbk btrbk"
        "A /nix/var/nix/profiles - - - - u:nix-gc:rwx,d:u:nix-gc:rwx,m::rwx,d:m::rwx"
        "d /var/lib/zerotier-one 700 zerotierd zerotierd"
        "Z /var/lib/zerotier-one - zerotierd zerotierd"
        "d /var/lib/zerotier-one/networks.p 700 zerotierd zerotierd"
      ] ++ map (netId: "f /var/lib/zerotier-one/networks.p/${netId}.conf 700 zerotierd zerotierd") config.services.zerotierone.joinNetworks;
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
      openvswitch = {
        isSystemUser = true;
        group = "openvswitch";
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
      openvswitch = {};
      tailscale = {};
      vfio = {};
      zerotierd = {};
    };
    users = {
      max = {
        extraGroups = [ "wheel" "dialout" "networkmanager" "plugdev" "video" "adbusers" "wireshark" ];
        isNormalUser = true;
        packages = with pkgs; [
          ardour
          authenticator
          btop
          cargo-watch
          ungoogled-chromium
          cifs-utils
          ciscoPacketTracer8
          comma
          discord
          dwarf-fortress
          elinks
          emacs
          erlang
          file
          firefox
          firmware-manager
          gcc
          pkgsCross.aarch64-multiplatform.buildPackages.gcc
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc
          pkgsCross.riscv32.buildPackages.gcc
          pkgsCross.riscv64.buildPackages.gcc
          gdb
          pkgsCross.aarch64-multiplatform.buildPackages.gdb
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gdb
          pkgsCross.riscv32.buildPackages.gdb
          pkgsCross.riscv64.buildPackages.gdb
          (haskellPackages.ghcWithPackages (pkgs: with pkgs; [ aeson monoidal-containers optparse-applicative statistics vector yaml]))
          # inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.pkgsCross.ghcjs.buildPackages.haskell.compiler.ghc961
          gnome.ghex
          gnome.gnome-tweaks
          graphviz
          gtkterm
          guile_3_0
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.guile-hall
          # inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.guix
          # (haskell-language-server.override {supportedGhcVersions = ["90" "927" "944" "945"];})
          hpack
          headsetcontrol
          inputs.haskell-nix.packages.x86_64-linux.hix
          htop
          inputs.keyboard_mouse_emulate_on_raspberry.packages.x86_64-linux.default
          lfe
          libsoup_3
          libxml2
          libreoffice-fresh
          liburing
          libvirt
          linux-manual
          lshw
          lsof
          (man-pages.overrideAttrs ({patches ? [], ...}: {
            patches = patches ++ [ ./fs-manpages.patch ];
          }))
          maven
          mercurial
          meson
          mars-mips
          ninja
          niv
          nix-du
          nix-eval-jobs
          nix-prefetch
          nix-prefetch-scripts
          nix-top
          inputs.nixos-kexec.packages.x86_64-linux.default
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.minimal-bootstrap.mescc-tools
          mixxx
          nmap
          nodejs
          notepadqq
    #      (import inputs.obelisk {system = "x86_64-linux";}).command
          ocaml
          ormolu
          oversteer
          p7zip
          pango
          pijul
          pioneer
          plantuml
          plover.dev
          powertop
          prismlauncher
          #polymc
          python3
          qemu
          qlcplus
          qpdfview
          qtspim
          rebar3
          ripgrep
          inputs.rename-exchange.packages.x86_64-linux.default
          inputs.math104.packages.x86_64-linux.rEnv
          rfc
          rhythmbox
          inputs.math104.packages.x86_64-linux.rstudioEnv
          rustup
          rust-analyzer
          scummvm
          shellcheck
          signal-desktop
          simple-http-server
          simutrans
          inputs.shh.packages.x86_64-linux.default
          snis
          sshfs
          stack
          tea
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.teams-for-linux
          #teams
          #texlive.combined.scheme-full
          inputs.tobig.packages.x86_64-linux.default
          thunderbird
          nodePackages.uglify-js
          umlet
          usbutils
          vdrift
          vim
          vlc
          (vscode-with-extensions.override {
            vscode = vscodium;
            vscodeExtensions =
              let exts = inputs.vscode-extensions.extensions.${system}.vscode-marketplace; in
                builtins.attrValues {
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
          vulnix
          w3m
          watchexec
    #      wine
          winetricks
          #((wineWowPackages.full.override {sdlSupport = true; vkd3dSupport = true;}).overrideAttrs (_: {patches = [./attachment.cgi];}))
          wineWowPackages.full
          wireshark
          wl-clipboard
          xclip
    #      xfel
          yacas
    #      (import (pkgs.fetchurl {url = "https://github.com/input-output-hk/haskell.nix/tarball/master";})).hix
          xorg.xhost
          zgrviewer
        ];
        shell = pkgs.fish;
      };
    };
  };
  virtualisation = {
    vmVariant = {
      users = {
        users = {
          max = {
            password = "nixos";
          };
        };
      };
    };
    vswitch = {
      package = inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.openvswitch;
    };
  };
  zramSwap = {
    algorithm = "zstd";
    enable = true;
    memoryPercent = 100;
    priority = 5;
  };
}
