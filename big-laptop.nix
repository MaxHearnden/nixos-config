{ pkgs, lib, ... }:

{
  boot = {
    extraModprobeConfig = "options iwlwifi 11n_disable=1";
    kernelPackages = lib.mkForce pkgs.linuxPackages;
  };
  hardware = {
    graphics.extraPackages = [ pkgs.intel-media-driver pkgs.nvidia-vaapi-driver ];
    nvidia.open = true;
    tuxedo-drivers = {
      enable = true;
    };
  };
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  networking = {
    firewall.interfaces.enp45s0 = {
      allowedTCPPorts = [ 9943 9944 ];
      allowedUDPPorts = [ 67 9943 9944 ];
    };
    hostName = "max-nixos-laptop";
  };
  nix = {
    buildMachines = [
      {
        hostName = "workstation.zandoodle.me.uk";
        maxJobs = 16;
        protocol = "ssh-ng";
        sshUser = "nix-ssh";
        supportedFeatures = [ "nixos-test" "benchmark" "big-parallel" "kvm" ];
        systems = [
          "x86_64-linux" "armv7l-linux" "aarch64-linux" "mips-linux"
          "mipsel-linux" "mips64-linux" "mips64el-linux" "riscv32-linux"
          "riscv64-linux" "i686-linux"
        ];
      }
    ];
    distributedBuilds = true;
    settings = {
      avoid-local = true;
      builders-use-substitutes = true;
    };
  };
  security.tpm2 = {
    enable = true;
    tctiEnvironment.enable = true;
  };
  services = {
    logind.settings.Login.HandleLidSwitch = "ignore";
    xserver.videoDrivers = [ "nvidia" ];
  };
}
