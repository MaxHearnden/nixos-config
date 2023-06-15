{ config, pkgs, inputs, lib, ... }:

{
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
    kernelPackages = pkgs.linuxKernel.packages.linux_6_1;
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
  environment = {
    systemPackages = with pkgs; [
      gitFull
    ];
  };
  fileSystems = {
    "/home/max/h-drive" = {
      device = "//homes.lancs.ac.uk/04/hearndem";
      fsType = "cifs";
      options = [
        "defaults"
        "uid=max"
        "gid=users"
        "cred=/root/lancaster-creds"
        "mfsymlinks"
        "nofail"
      ];
    };
    "/home/max/shared" = {
      device = "172.28.10.244:/Big/shared";
      fsType = "nfs";
      options = [
        "defaults"
        "x-systemd.requires=sys-devices-virtual-net-ztmjfp7kiq.device"
        "x-systemd.after=zerotierone.service"
        "nofail"
        "fsc"
        "softreval"
        "async"
      ];
    };
  };
  hardware = {
    enableAllFirmware = true;
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
    settings = {
      auto-optimise-store = true;
      experimental-features = [
        "nix-command"
        "flakes"
      ];
      trusted-public-keys = [ "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI=" ];
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
    adb = {
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
  };
  security = {
    doas = {
      enable = true;
    };
  };
  services = {
    cachefilesd = {
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
    openssh = {
      settings = {
        X11Forwarding = true;
      };
    };
    sshd = {
      enable = true;
    };
    xserver = {
      desktopManager = {
        gnome = {
          enable = true;
        };
      };
      displayManager = {
        gdm = {
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
      inputs.haskell-nix.inputs.nixpkgs
      inputs.nixpkgs
    ];
    stateVersion = "23.05";
  };
  time = {
    timeZone = "Europe/London";
  };
  users = {
    extraUsers = {
      sh = {
        description = "A user to allow for ~sh instead of ~/shared";
        group = "sh";
        home = "/home/max/shared";
        isSystemUser = true;
      };
    };
    groups = {
      sh = {};
    };
    users = {
      max = {
        extraGroups = [ "wheel" "dialout" "networkmanager" "plugdev" "video" "adbusers" ];
        isNormalUser = true;
        packages = with pkgs; [
          ardour
          authenticator
          bc
          binutils
          btop
          cabal2nix
          cargo-watch
          ungoogled-chromium
          cifs-utils
          darcs
          discord
          dwarf-fortress
          emacs
          file
          firefox
          fossil
          pkgsCross.aarch64-multiplatform.buildPackages.gcc
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc
          pkgsCross.mipsel-linux-gnu.buildPackages.gcc
          pkgsCross.mips64el-linux-gnuabi64.buildPackages.gcc
          pkgsCross.riscv32.buildPackages.gcc
          pkgsCross.riscv64.buildPackages.gcc
          gdb
          pkgsCross.aarch64-multiplatform.buildPackages.gdb
          pkgsCross.armv7l-hf-multiplatform.buildPackages.gdb
          pkgsCross.mipsel-linux-gnu.buildPackages.gdb
          pkgsCross.mips64el-linux-gnuabi64.buildPackages.gdb
          pkgsCross.riscv32.buildPackages.gdb
          pkgsCross.riscv64.buildPackages.gdb
          gcc
          (haskellPackages.ghcWithPackages (pkgs: with pkgs; [ aeson monoidal-containers optparse-applicative statistics vector yaml]))
          # inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.pkgsCross.ghcjs.buildPackages.haskell.compiler.ghc961
          gnome.ghex
          ghidra
          giac-with-xcas
          gnome.gnome-tweaks
          gimp
          git-cola
          golly
          graphviz
          gtkterm
          guile_3_0
          (haskell-language-server.override {supportedGhcVersions = ["90" "927" "944" "945"];})
          hpack
          headsetcontrol
          inputs.haskell-nix.packages.x86_64-linux.hix
          htop
          jdk
          libelf
          libreoffice-fresh
          libtool
          linux-manual
          lshw
          man-pages
          mercurial
          mars-mips
          niv
          nix-du
          nix-eval-jobs
          nix-prefetch
          nix-prefetch-scripts
          nix-top
          nmap
          node2nix
          nodejs
          notepadqq
    #      (import inputs.obelisk {system = "x86_64-linux";}).command
          ocaml
          openocd
          ormolu
          pijul
          pioneer
          plover.dev
          pkg-config
          prismlauncher
          #polymc
          qemu
          qpdfview
          qtspim
          # rWrapper
          inputs.math104.packages.x86_64-linux.rEnv
          rhythmbox
          inputs.math104.packages.x86_64-linux.rstudioEnv
          rustup
          rust-analyzer
          simple-http-server
          simutrans
          snis
          stack
          tea
          #teams
          #texlive.combined.scheme-full
          thunderbird
          usbutils
          vdrift
          vim
          vlc
          (vscode-with-extensions.override {
            vscode = vscodium;
            vscodeExtensions =
              let exts = inputs.vscode-extensions.extensions.${system}.vscode-marketplace; in
                builtins.attrValues {
                  inherit (exts.rust-lang) rust-analyzer;
                  inherit (exts.haskell) haskell;
                  inherit (exts.justusadam) language-haskell;
                  inherit (exts.jnoortheen) nix-ide;
                  inherit (exts.maelvalais) autoconf;
                  inherit (exts.prince781) vala;
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
          segger-jlink
          zgrviewer
        ];
      };
    };
  };
}
