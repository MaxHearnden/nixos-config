{ ... }: {
  imports = [ ./hardware-configuration/laptop.nix ./laptop.nix ./remote.nix ];
  boot.loader.grub.useOSProber = true;
  extraEntries = ''
    menuentry "iPXE" {
      chainloader @bootRoot@/ipxe.efi
    }
  '';
  extraFiles."ipxe.efi" = "${pkgs.ipxe}/ipxe.efi";
  hardware.tuxedo-keyboard.enable = true;
  services.logind.libSwitch = "ignore";
  fileSystems."/mnt/ubuntu" = {
    device = "/dev/nvme1n1p1";
    fsType = "ext4";
    options = [ "nofail" "ro" ];
  };
  services.xserver.videoDrivers = [ "nvidia" ];
}
