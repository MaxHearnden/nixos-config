{ inputs, ... }:

{
  system.extraSystemBuilderCmds = let
    pcrlock = "${inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.systemd.out}/lib/systemd/systemd-pcrlock";
  in ''
    # Lock bootloader
    ${pcrlock} lock-pe $out/systemd/lib/systemd/boot/efi/systemd-bootx64.efi --pcrlock=$out/650-systemd-boot.pcrlock
    # Lock kernel
    ${pcrlock} lock-pe $out/kernel --pcrlock=$out/670-kernel.pcrlock
    # Lock command line
    initrd_suffix=$(basename $(readlink $out/initrd))
    initrd=$(basename $(dirname $(readlink $out/initrd)))
    echo "initrd=\\efi\\nixos\\$initrd-$initrd_suffix.efi $(<$out/kernel-params)" | ${pcrlock} lock-kernel-cmdline /dev/stdin --pcrlock=$out/710-kernel-cmdline.pcrlock
    # Lock command line round two (Covers pcr 11)
    sed 's/"pcr":9/"pcr":11/' <$out/710-kernel-cmdline.pcrlock >$out/705-kernel-cmdline.pcrlock
    # Lock initrd
    ${pcrlock} lock-kernel-initrd $out/initrd --pcrlock=$out/720-kernel-initrd.pcrlock
  '';
}
