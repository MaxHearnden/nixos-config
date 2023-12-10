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
    kernelPackages = pkgs.linuxKernel.packageAliases.linux_latest;
    extraModulePackages = [
      config.boot.kernelPackages.rtl8812au
      config.boot.kernelPackages.rtl88x2bu
    ];
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
  fileSystems = {
    "/" = {
      options = [ "noatime" ];
    };
    "/home/max/h-drive" = {
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
      ];
    };
    "/home/max/shared" = {
      device = "172.28.10.244:/Big/shared";
      fsType = "nfs";
      options = [
        "defaults"
        "x-systemd.requires=sys-devices-virtual-net-ztmjfp7kiq.device"
        "x-systemd.requires=zerotierone.service"
        "nofail"
        "fsc"
        "softreval"
        "async"
      ];
    };
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
  krb5 = {
    domain_realm = {
      "172.28.10.244" = "WORKSTATION";
      "max-nixos-workstation" = "WORKSTATION";
    };
    enable = true;
    libdefaults = {
      default_realm = "WORKSTATION";
      ignore_acceptor_hostname = true;
    };
    realms = {
      WORKSTATION = {
        kdc = [
          "172.28.10.244"
        ];
      };
    };
  };
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
    registry.nixpkgs.flake = inputs.nixpkgs;
    settings = {
      auto-optimise-store = true;
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
      "172.28.10.244" = ["max-nixos-workstation"];
      "172.28.198.106" = ["max-nixos-laptop"];
      "172.28.156.146" = ["max-nixos-chromebooksd2"];
      "172.28.12.138" = ["max-nixos-dell"];
      "172.28.13.156" = ["max-nixos-pc"];
      "172.28.11.61" = ["max-guix-chromebook"];
      "172.28.128.58" = ["max-guix-dell"];
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
      "mount.nfs" = {
        source = "${pkgs.nfs-utils}/bin/mount.nfs";
        owner = "root";
        group = "root";
        setuid = true;
      };
    };
  };
  services = {
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
    kmscon = {
      enable = true;
      extraOptions = "--xkb-layout gb";
    };
    ntp = {
      enable = true;
    };
    openssh = {
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
      ./.
    ];
    stateVersion = "23.05";
  };
  systemd = {
    services = {
      nix-gc = {
        serviceConfig = {
          BindReadOnlyPaths = "/nix/var/nix/daemon-socket";
          BindPaths = "/nix/var/nix/profiles";
          User = "nix-gc";
          Group = "nix-gc";
          ProtectHome = "tmpfs";
          NoNewPrivileges = true;
          RestrictAddressFamilies = "AF_UNIX";
          Environment = "HOME=/home/nix-gc";
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
      };
      wpa_supplicant = {
        serviceConfig = {
          RootDirectory = "/var/empty";
          TemporaryFileSystem = "/";
          SystemCallArchitectures = "native";
          NoNewPrivileges = true;
          PrivateMounts = true;
          MountAPIVFS = true;
          BindReadOnlyPaths = "/nix/store /run/dbus/system_bus_socket";
          RestrictNamespaces = true;
          CapabilityBoundingSet = "CAP_NET_ADMIN";
        };
      };
      nix-daemon = {
        serviceConfig = {
          CapabilityBoundingSet = "CAP_SYS_CHROOT CAP_CHOWN CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_FOWNER";
          ProtectSystem = "strict";
          BindPaths = "/dev/kvm";
          # RootDirectory = "/var/empty";
          # TemporaryFileSystem = "/";
          # BindReadOnlyPaths = "/etc/nix /etc/resolv.conf /etc/ssl /etc/static/ssl /etc/passwd /etc/group /machines";
          # BindPaths = "/nix /root/.cache/nix /tmp";
          ReadWritePaths = "/nix /root/.cache/nix /tmp";
          RestrictAddressFamilies = "AF_UNIX AF_INET AF_INET6";
          # PrivateMounts = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          SocketBindDeny = "any";
          RestrictNamespaces = "user net mnt ipc pid uts";
        };
      };
      tailscaled = {
        serviceConfig = {
          UMask = "0077";
          BindPaths = "/var/lib/tailscale";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /etc/static/ssl";
          User = "tailscale";
          Group = "tailscale";
          DeviceAllow = ["/dev/tun" "/dev/net/tun"];
          AmbientCapabilities = "CAP_NET_RAW CAP_NET_ADMIN";
          # ProtectKernelModules = true;
          ProtectProc = [ "invisible" ];
          SystemCallFilter = [ "@system-service" "~@privileged" ];
          PrivateDevices = lib.mkForce false;
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
          ProcSubset = "pid";
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
          BindPaths = "/var/lib/zerotier-one";
          BindReadOnlyPaths = "/etc/resolv.conf /etc/ssl /etc/static/ssl";
          DeviceAllow = ["/dev/tun" "/dev/net/tun"];
          AmbientCapabilities = "CAP_NET_RAW CAP_NET_ADMIN";
          # ProtectKernelModules = true;
          ProtectProc = [ "invisible" ];
          SystemCallFilter = [ "@system-service" ];
          PrivateDevices = lib.mkForce false;
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
          CapabilityBoundingSet = "CAP_NET_RAW CAP_NET_ADMIN";
          ProcSubset = "pid";
          ExecStart = lib.mkForce "${config.services.zerotierone.package}/bin/zerotier-one -p${toString config.services.zerotierone.port} -U";
          ExecStartPre = lib.mkForce [];
          User = "zerotierd";
          Group = "zerotierd";
          RemoveIPC = true;
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
        "A+ /nix/var/nix/profiles - - - - u:nix-gc:rwx"
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
      zerotierd = {};
    };
    users = {
      max = {
        extraGroups = [ "wheel" "dialout" "networkmanager" "plugdev" "video" "adbusers" "wireshark" ];
        isNormalUser = true;
        packages = with pkgs; [
          ardour
          authenticator
          bc
          btop
          cabal-install
          cabal2nix
          cairo
          cargo-watch
          ungoogled-chromium
          cifs-utils
          darcs
          dbus
          discord
          dwarf-fortress
          elinks
          elmPackages.elm
          elm2nix
          emacs
          erlang
          file
          firefox
          firmware-manager
          fossil
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
          gtk4
          github-cli
          ghidra
          giac-with-xcas
          gnome.gnome-tweaks
          gimp
          git-cola
          golly
          gradle
          graphviz
          gtkterm
          guile_3_0
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.guile-hall
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.guix
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
          linux-manual
          lshw
          man-pages
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
          qemu
          qlcplus
          qpdfview
          qtspim
          rebar3
          inputs.math104.packages.x86_64-linux.rEnv
          rhythmbox
          inputs.math104.packages.x86_64-linux.rstudioEnv
          rustup
          rust-analyzer
          scummvm
          shellcheck
          signal-desktop
          simple-http-server
          simutrans
          snis
          sshfs
          stack
          tea
          inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.teams-for-linux
          #teams
          #texlive.combined.scheme-full
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
  zramSwap = {
    algorithm = "zstd";
    enable = true;
    memoryPercent = 100;
    priority = 5;
  };
}
