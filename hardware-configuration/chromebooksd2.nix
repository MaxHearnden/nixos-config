# Do not modify this file!  It was generated by ‘nixos-generate-config’
# and may be overwritten by future invocations.  Please make changes
# to /etc/nixos/configuration.nix instead.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/installer/scan/not-detected.nix")
    ];

  boot.initrd.availableKernelModules = [ "xhci_pci" "sdhci_pci" "usb-storage" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/31008dc8-45bd-4072-9328-e2b3496294d2";
      fsType = "btrfs";
      options = ["compress=zstd"]
    };

  fileSystems."/nix" = {
    device = "/dev/disk/by-uuid/31008dc8-45bd-4072-9328-e2b3496294d2";
    fsType = "btrfs";
    options = ["defaults" "subvol=/nix" "noatime" "compress=zstd"];
  };

  boot.loader.grub.copyKernels = true;

  fileSystems."/boot/efi" =
    { device = "/dev/disk/by-uuid/02A5-E2B4";
      fsType = "vfat";
    };

  swapDevices = [ ];

  # Enables DHCP on each ethernet and wireless interface. In case of scripted networking
  # (the default) this is the recommended approach. When using systemd-networkd it's
  # still possible to use this option, but it's recommended to use it in conjunction
  # with explicit per-interface declarations with `networking.interfaces.<interface>.useDHCP`.
  networking.useDHCP = lib.mkDefault true;
  # networking.interfaces.wlp2s0.useDHCP = lib.mkDefault true;

  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
}
