{ pkgs, ... }: {
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  networking.hostName = "max-nixos-laptop";
  boot.loader.grub = {
    useOSProber = true;
  };
  hardware.tuxedo-keyboard.enable = true;
  services.logind.lidSwitch = "ignore";
  fileSystems."/mnt/ubuntu" = {
    device = "/dev/nvme1n1p1";
    fsType = "ext4";
    options = [ "nofail" "ro" ];
  };
  #specialisation.nvidia.configuration = {
  #  services.xserver.videoDrivers = [ "nvidia" ];
  #  #system.autoUpgrade.flags = [ "-c" "nvidia" ];
  #  hardware.nvidia.prime.nvidiaBusId = "PCI:1:0:0";
  #  hardware.nvidia.prime.intelBusId = "PCI:0:2:0";
  #  hardware.nvidia.prime.sync.enable = true;
  #};

  services.xserver.videoDrivers = [ "nvidia" ];

  hardware.nvidia.prime = {
    nvidiaBusId = "PCI:1:0:0";
    intelBusId  = "PCI:0:2:0";
    # sync.enable = true;
    offload.enable = true;
  };

  #inprove compatibility with windows
  time.hardwareClockInLocalTime = true;
  boot.extraModprobeConfig = "options iwlwifi 11n_disable=1";
}
