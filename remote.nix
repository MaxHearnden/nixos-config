{ config, pkgs, lib, ... }: {
  imports = [./configuration.nix];
  nix.settings = {
    trusted-public-keys = ["max-nixos-workstation:Ds5AWfGPm6jRbVSjG4ht42MK++hhfFczQ4bJRhD9thI="];
    substituters = ["http://172.28.10.244:8080"];
  };
  nix.buildMachines = [
    {
      systems = [ "riscv64-linux" "mips-linux" "mipsel-linux" "mips64-linux" "mips64el-linux" "aarch64-linux" "riscv32-linux" "x86_64-linux" "i686-linux" ];
      sshUser = "root";
      hostName = "172.28.10.244";
      maxJobs = 4;
      supportedFeatures = [ "kvm"
        "big-parallel"
        "benchmark"
        "nixos-test"
      ];
    }
  ];
  nix.distributedBuilds = true;

}
