{ pkgs, lib, ...}: {
  boot = {
    loader = {
      grub = {
        enable = lib.mkForce false;
      };
      systemd-boot = {
        enable = true;
      };
    };
  };
  hardware = {
    acpilight = {
      enable = true;
    };
  };
}
