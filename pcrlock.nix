{ inputs, lib, ... }:

{
  system.systemBuilderCommands = let
    pcrlock = "${inputs.nixpkgs-unstable.legacyPackages.x86_64-linux.systemd.out}/lib/systemd/systemd-pcrlock";
  in lib.mkAfter ''
    # Lock bootloader
    ${pcrlock} lock-pe $out/systemd/lib/systemd/boot/efi/systemd-bootx64.efi --pcrlock=$out/650-systemd-boot.pcrlock
    # Lock kernel
    ${pcrlock} lock-pe $out/kernel --pcrlock=$out/670-kernel.pcrlock
    # Lock command line
    initrd_suffix=$(basename $(readlink $out/initrd))
    initrd=$(basename $(dirname $(readlink $out/initrd)))
    kernel_params="initrd=\\efi\\nixos\\$initrd-$initrd_suffix.efi init=$out/init $(<$out/kernel-params)"
    echo "$kernel_params"
    ${pcrlock} lock-kernel-cmdline <(echo "$kernel_params") --pcrlock=$out/710-kernel-cmdline.pcrlock
    # Lock command line round two (Covers pcr 11)
    sed 's/"pcr":9/"pcr":12/' <$out/710-kernel-cmdline.pcrlock >$out/705-kernel-cmdline.pcrlock
    # Lock initrd
    ${pcrlock} lock-kernel-initrd $out/initrd --pcrlock=$out/720-kernel-initrd.pcrlock
  '';
}
