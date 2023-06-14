# add grub entries for a guix system
{
  boot = {
    loader = {
      grub = {
        extraEntries = ''
          menuentry "Guix" {
            search --fs-uuid --set F5DE-4023
            chainloader /EFI/Guix/grubx64.efi
          }
        '';
      };
    };
  };
}
