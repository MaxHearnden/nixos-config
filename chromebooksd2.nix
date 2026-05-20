{ lib, pkgs, ... }:

{
  boot = {
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
      efi = {
        canTouchEfiVariables = lib.mkForce false;
      };
    };
  };
  imports = [ ./remote.nix ./hardware-configuration/chromebooksd2.nix ./laptop.nix ];
  networking = {
    hostName = "max-nixos-chromebooksd2";
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
  services.ip-mesh = {
    self = lib.mkForce "chromebook";
  };
  swapDevices = [
    {
      device = "/nexus/swapfile";
    }
  ];
}
