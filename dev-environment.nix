{ pkgs, ... }: {
  users = {
    users = {
      max = {
        packages = with pkgs; [
          (myEnvFun {
            name = "dev";
            buildInputs = [
              autoconf
              automake
              bison
              flex
              gettext
              libtool
              meson
              pkg-config
              vala
            ] ++ [
              atk
              dbus
              cairo
              freetype
              glib
              gtk3
              gtk4
              libgee
              libsoup
              libsoup_3
              libxml
              pango
              SDL2
            ];
          })
        ];
      };
    };
  };
}
