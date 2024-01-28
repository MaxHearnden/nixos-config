# Do not modify this file!  It was generated by ‘nixos-generate-config’
# and may be overwritten by future invocations.  Please make changes
# to /etc/nixos/configuration.nix instead.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/installer/scan/not-detected.nix")
    ];

  boot.initrd.availableKernelModules = [ "xhci_pci" "ahci" "usbhid" "usb_storage" "sd_mod" "sr_mod" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/76463411-5c55-4708-bf63-7e3195776b57";
      fsType = "btrfs";
      options = [ "compress=zstd" "subvol=/@NixOS" ];
    };

  fileSystems."/boot/efi" =
    { device = "/dev/disk/by-uuid/9AF6-12D3";
      fsType = "vfat";
    };

  fileSystems."/Big" =
    { device = "/dev/disk/by-uuid/0379ef59-faa8-424c-89a7-cedc93956adc";
      fsType = "btrfs";
      options = [ "defaults" "compress=zstd" "noatime" "user_subvol_rm_allowed" ];
    };

  fileSystems."/nix" =
    { device = "/dev/disk/by-uuid/76463411-5c55-4708-bf63-7e3195776b57";
      fsType = "btrfs";
      options = [ "defaults" "subvol=/nix" "noatime" "compress=zstd" ];
    };

  # swapDevices = [ { device = "/dev/disk/by-uuid/1ef934f7-1630-4889-8a13-8a2cbebebcc2"; } ];

  # Enables DHCP on each ethernet and wireless interface. In case of scripted networking
  # (the default) this is the recommended approach. When using systemd-networkd it's
  # still possible to use this option, but it's recommended to use it in conjunction
  # with explicit per-interface declarations with `networking.interfaces.<interface>.useDHCP`.
  networking.useDHCP = lib.mkDefault true;
  # networking.interfaces.eno1.useDHCP = lib.mkDefault true;
  # networking.interfaces.enp1s0.useDHCP = lib.mkDefault true;

  powerManagement.cpuFreqGovernor = lib.mkDefault "powersave";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
}
