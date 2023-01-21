# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, inputs, lib, ... }:

{
  hardware.enableAllFirmware = true;
#  imports =
#    [ # Include the results of the hardware scan.
#      ./hardware-configuration.nix
#    ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.grub = {
    enable = true;
    version = 2;
    device = "nodev";
    efiSupport = true;
  };
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.efi.efiSysMountPoint = "/boot/efi";
  boot.binfmt.emulatedSystems = [ "riscv64-linux" "mips-linux" "mipsel-linux" "mips64-linux" "mips64el-linux" "aarch64-linux" "riscv32-linux" ];
#  boot.kernelPackages = (import ./kgdb_kernel.nix).packages;
  nixpkgs.config.allowUnfree = true;
  nixpkgs.config.segger-jlink.acceptLicense = true;
  services.sshd.enable = true;

  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  # networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "Europe/London";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_GB.utf8";
  console = {
#    enable = false;
#    font = "Lat2-Terminus16";
    keyMap = "uk";
#    useXkbConfig = true; # use xkbOptions in tty.
  };

  # Enable the X11 windowing system.
  services.xserver.enable = true;


  # Enable the GNOME Desktop Environment.
#  services.xserver.autorun = false;
  services.xserver.displayManager.gdm.enable = true;
  services.xserver.desktopManager.gnome.enable = true;
  services.xserver.windowManager.i3.enable = true;
  services.xserver.windowManager.xmonad.enable = true;
  

  # Configure keymap in X11
  services.xserver.layout = "gb";
  # services.xserver.xkbOptions = {
  #   "eurosign:e";
  #   "caps:escape" # map caps to escape.
  # };

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # sound.enable = true;
  # hardware.pulseaudio.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.max = {
    isNormalUser = true;
    extraGroups = [ "wheel" "dialout" "networkmanager" "plugdev" "video" ]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      authenticator
      bc
      binutils
      btop
      cabal2nix
      cabal-install
      cargo-watch
      chromium
      cifs-utils
      discord
      emacs
      file
      firefox
      gdb
      gnome.ghex
      ghidra
      giac-with-xcas
      gnome.gnome-tweaks
      gimp
      gitFull
      git-cola
      golly
      graphviz
      gtkterm
      #(pkgs.haskell-language-server.override {supportedGhcVersions = ["810" "90" "924" "94" "943"];})
      haskell-language-server
      hpack
      headsetcontrol
      inputs.haskell-nix.packages.x86_64-linux.hix
      htop
      jdk
      libreoffice-fresh
      lshw
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
      pioneer
      plover.dev
      prismlauncher
      #polymc
      qemu
      rWrapper
      rhythmbox
      rstudio
      rustup
      rust-analyzer
      simple-http-server
      simutrans
      snis
      stack
      teams
      #texlive.combined.scheme-full
      thunderbird
      usbutils
      vdrift
      vim
      vlc
      (vscode-with-extensions.override {
        vscode = vscodium;
        vscodeExtensions = with vscode-extensions;
        [matklad.rust-analyzer haskell.haskell justusadam.language-haskell];
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
  programs.neovim.enable = true;
  programs.neovim.configure = {
    customRC = ''
      set mouse=a
      set shiftwidth=2
      set expandtab
    '';
#      lua vim.lsp.start ({name = 'haskell', cmd = {'${pkgs.haskell-language-server}'}, root_dir = vim.fs.dirname (vim.fs.find ({'hie.yaml'})[1])})
    packages.haskell = with pkgs.vimPlugins; {
      start = [ nvim-lspconfig ];
    };
  };
  programs.neovim.defaultEditor = true;
  programs.neovim.withNodeJs = true;
  programs._1password.enable = true;
  programs._1password-gui.enable = true;

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  # environment.systemPackages = with pkgs; [
  #   vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #   wget
  # ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;
  system.extraDependencies = [inputs.haskell-nix.inputs.nixpkgs inputs.nixpkgs ];

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "22.05"; # Did you read the comment?

  programs.steam.enable = true;
  services.zerotierone = {
    joinNetworks = [ "8056c2e21c3d4b0c" ];
    enable = true;
  };
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
/*  nix.buildMachines = [
    {
      systems = ["riscv64-linux" "x86_64-linux" "i686-linux" "mipsel-linux" "mips64el-linux" ];
      sshUser = "root";
      sshKey = "/var/lib/hydra/queue-runner/.ssh/id_rsa";
      hostName = "127.0.0.1";
      maxJobs = 4;
      supportedFeatures = [ "kvm"
        "big-parallel"
        "benchmark"
        "nixos-test"
      ];
    }
    {
      systems = ["riscv64-linux" "x86_64-linux" "i686-linux" "mipsel-linux" "mips64el-linux" ];
      sshUser = "root";
      sshKey = "/var/lib/hydra/queue-runner/.ssh/id_rsa";
      hostName = "192.168.2.2";
      maxJobs = 8;
      speedFactor = 2;
      supportedFeatures = [ "kvm"
        "big-parallel"
        "bechmark"
        "nixos-test"
      ];
    }
  ];*/
  nix.settings.auto-optimise-store = true;
  nix.gc.automatic = true;
  nix.gc.options = "--delete-older-than 7d";
  nix.gc.persistent = true;
  nix.settings.substituters = lib.mkAfter [ "https://nixcache.reflex-frp.org" ];
  nix.settings.trusted-public-keys = [ "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI=" ];
  security.doas.enable = true;
  system.autoUpgrade.enable = true;
  system.autoUpgrade.allowReboot = true;
  system.autoUpgrade.dates = "17:45";
  system.autoUpgrade.persistent = true;
  #system.autoUpgrade.flake = "/etc/nixos";
  system.autoUpgrade.flags = ["--update-input" "nixpkgs" "--refresh" "--no-write-lock-file"];
#  android_sdk.accept_licence = true;
  services.openssh.forwardX11 = true;

  systemd.services.nixos-upgrade.requires = ["zerotierone.service"];

  #containers.RedNix.nixpkgs = inputs.nixpkgs-unstable;
  #containers.RedNix.config =
  #  { ... }: {
  #    _module.args.inputs = inputs;
  #    imports = [inputs.RedNix.container];
  #    system.stateVersion = "22.05";
  #  };
  #containers.mipsel.nixpkgs = nixpkgs-mipsel;
  #containers.mipsel.config =
  #  { pkgs, lib, ... } @ args:{
  #    system.stateVersion = "22.11";
  #    nixpkgs.hostPlatform.system = "mipsel-linux";
  #    nix.enable = false;
  #    documentation.enable = false;
  #    environment.systemPackages = [
  #      pkgs.file
  #    ];
  #  };
  #services.mysql.enable = true;
  #services.mysql.package = pkgs.mysql80;
  #services.mysql.ensureUsers = [ {name = "max"; ensurePermissions = {"*.*" = "ALL PRIVILEGES";};} ];
  #virtualisation.waydroid.enable = true;
  system.autoUpgrade.flake = "git+http://172.28.10.244:3000/zandoodle/nixos-config";

  specialisation.nox.configuration.services.xserver.autorun = false;

  services.kmscon.enable = true;
  services.kmscon.extraOptions = "--xkb-layout gb";

  fileSystems."/home/max/shared" = {
    device = "172.28.10.244:/Big/shared";
    options = ["defaults" "x-systemd.requires=sys-devices-virtual-net-ztmjfp7kiq.device" "x-systemd.requires=zerotierone.serivce" "nofail" "_netdev"];
    fsType = "nfs";
  };

  fileSystems."/home/max/h-drive" = {
    device = "//homes.lancs.ac.uk/04/hearndem";
    options = ["defaults" "uid=max" "gid=users" "cred=/root/lancaster-creds" "mfsymlinks" "nofail"];
    fsType = "cifs";
  };

}
