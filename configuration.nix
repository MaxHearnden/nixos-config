# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, inputs, lib, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

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

  networking.hostName = "max-nixos-workstation"; # Define your hostname.
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
  services.xserver.displayManager.gdm.autoSuspend = false;
  services.xserver.desktopManager.gnome.enable = true;
  services.xserver.windowManager.i3.enable = true;
  services.xserver.windowManager.xmonad.enable = true;
  services.xserver.displayManager.sessionCommands = "xhost +SI:localuser:max";
  networking.firewall.allowedUDPPorts = [ 25565 ];
  networking.firewall.allowedTCPPorts = [ 25565 ];
  networking.firewall.interfaces.ztmjfp7kiq.allowedTCPPorts = [ 8080 8081 50000 3000 3389 ];
  services.xserver.xrandrHeads = [ "HDMI-3" "HDMI-2" ];
  

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
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.max = {
    isNormalUser = true;
    extraGroups = [ "wheel" "dialout" ]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      authenticator
      bc
      binutils
      cabal2nix
      cabal-install
      chromium
      discord
      emacs
      file
      firefox
      gdb
      gnome.ghex
      ghidra
      gnome.gnome-tweaks
      gitFull
      git-cola
      golly
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
      niv
      nix-eval-jobs
      nix-prefetch
      nix-prefetch-scripts
      nix-top
      nmap
      node2nix
      nodejs
#      (import inputs.obelisk {system = "x86_64-linux";}).command
      ocaml
      openocd
      ormolu
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
      texlive.combined.scheme-full
      thunderbird
      usbutils
      vdrift
      vim
      (vscode-with-extensions.override {
        vscode = vscodium;
        vscodeExtensions = with vscode-extensions;
        [matklad.rust-analyzer haskell.haskell justusadam.language-haskell];
      })
      vulnix
      w3m
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
  environment.systemPackages = with pkgs; [
    gtk3
  ];

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

  services.hydra.enable = true;
  services.hydra.hydraURL = "http://172.28.10.244:8080";
  services.hydra.notificationSender = "hydra@example.com";
  services.hydra.listenHost = "172.28.10.244";
  services.hydra.port = 8080;
  services.hydra.extraConfig = ''
    binary_cache_secret_key_file = /etc/nix/storekey
    max_output_size = 8000000000
    Include /var/lib/hydra/gitea_authorisations.conf
  '';
  services.hydra.buildMachinesFiles = ["/machines"];
  services.hydra.useSubstitutes = true;
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
  nix.distributedBuilds = true;
  nix.settings.auto-optimise-store = true;
  nix.gc.automatic = true;
  nix.gc.options = "--delete-older-than 7d";
  nix.gc.persistent = true;
  nix.settings.substituters = lib.mkAfter [ "https://nixcache.reflex-frp.org" ];
  nix.settings.trusted-public-keys = [ "ryantrinkle.com-1:JJiAKaRv9mWgpVAz8dwewnZe0AzzEAzPkagE9SP5NWI=" ];
  security.doas.enable = true;
  system.autoUpgrade.enable = true;
  system.autoUpgrade.allowReboot = true;
  system.autoUpgrade.flake = "/etc/nixos";
  networking.interfaces.enp1s0.ipv4.addresses = [{address = "192.168.2.1"; prefixLength = 24;}];
  networking.interfaces.enp1s0.useDHCP = false;
  services.dhcpd4.enable = true;
  services.dhcpd4.interfaces = [ "enp1s0" ];
  services.dhcpd4.machines = [
    {
      ethernetAddress = "d4:93:90:06:43:76";
      hostName = "max-nixos-laptop";
      ipAddress = "192.168.2.2";
    }
/*    {
      ethernetAddress = "a0:36:9f:c3:d4:c1";
      hostName = "max-nixos-workstation";
      ipAddress = "192.168.2.1";
    }*/
  ];
  services.dhcpd4.extraConfig = ''
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.2.255;
    subnet 192.168.2.0 netmask 255.255.255.0 {
      range 192.168.2.10 192.168.2.250;
    }
  '';
  services.nix-serve.enable = true;
  services.nix-serve.openFirewall = true;
  services.nix-serve.bindAddress = "192.168.2.1";
  services.nix-serve.secretKeyFile = "/etc/nix/storekey";
  services.gitea = {
    enable = true;
    database.type = "postgres";
    settings.service.DISABLE_REGISTRATION = true;
    httpAddress = "172.28.10.244";
    domain = "172.28.10.244"
    rootUrl = "http://172.28.10.244:3000";
    settings.security.DISABLE_GIT_HOOKS=false;
#    useWizard = true;
  };
/*    host max-nixos-workstation {
      hardware ethernet a0:36:9f:c3:d4:c1;
      fixed-address 192.168.2.1;
    }*/
  services.xrdp.enable = true;
  services.xrdp.defaultWindowManager = "xmonad";
#  android_sdk.accept_licence = true;
  services.openssh.forwardX11 = true;
  environment.etc."nix/machines" = {
    source = "/machines";
  };

  networking.nat = {
    enable = true;
    internalInterfaces = [ "ve-rednix" ];
    externalInterface = "eno1";
  };
  networking.networkmanager.unmanaged = [ "interface-name:ve-rednix" ];
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
  services.ratbagd.enable = true;
  #services.mysql.enable = true;
  #services.mysql.package = pkgs.mysql80;
  #services.mysql.ensureUsers = [ {name = "max"; ensurePermissions = {"*.*" = "ALL PRIVILEGES";};} ];
  #virtualisation.waydroid.enable = true;

}
