# Do not modify this file!  It was generated by ‘nixos-generate-config’
# and may be overwritten by future invocations.  Please make changes
# to /etc/nixos/configuration.nix instead.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/installer/scan/not-detected.nix")
    ];

  boot.initrd.availableKernelModules = [ "xhci_pci" "ahci" "usbhid" "usb_storage" "sd_mod" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/23d34216-8396-41b9-ae01-290d9fbf1a6d";
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "subvol=/@NixOS" ];
    };

  fileSystems."/boot/efi" =
    { device = "/dev/disk/by-uuid/A6CD-C355";
      fsType = "vfat";
    };

  fileSystems."/var/guix" =
    { device = "/dev/disk/by-uuid/23d34216-8396-41b9-ae01-290d9fbf1a6d";
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "subvol=/var/@guix" ];
    }

  # swapDevices = [ { device = "/swapfile"; } ];

  # Enables DHCP on each ethernet and wireless interface. In case of scripted networking
  # (the default) this is the recommended approach. When using systemd-networkd it's
  # still possible to use this option, but it's recommended to use it in conjunction
  # with explicit per-interface declarations with `networking.interfaces.<interface>.useDHCP`.
  networking.useDHCP = lib.mkDefault true;
  # networking.interfaces.eno1.useDHCP = lib.mkDefault true;

  powerManagement.cpuFreqGovernor = lib.mkDefault "powersave";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
}
