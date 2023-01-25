{ pkgs, ...}: {
  hardware.acpilight.enable = true;
  users.users.max = {
    packages = with pkgs; [
      light
    ];
  };
}
