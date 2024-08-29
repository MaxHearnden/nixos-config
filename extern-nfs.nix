{ kernel }:

kernel.stdenv.mkDerivation {
  pname = "nfs";
  version = kernel.version;
  src = kernel.src;
  patches = [ ./null-kernel-warn.patch ];
  makeFlags = kernel.makeFlags ++ [
    "-C" "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "M=$(PWD)/fs/nfs"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    # "INSTALL_MOD_DIR=kernel/fs/nfs"
  ];
  enableParallelBuilding = true;
  installTargets = "modules_install";
}
