{ pkgs, ... }:

{
  environment = {
    systemPackages = with pkgs; [
      gns3-gui
    ];
  };
  programs = {
    fish = {
      enable = true;
      promptInit = "fish_vi_key_bindings";
    };
  };
  security = {
    sudo = {
      wheelNeedsPassword = false;
    };
  };
  services = {
    gns3-server = {
      dynamips = {
        enable = true;
      };
      enable = true;
      ubridge = {
        enable = true;
      };
    };
    xserver = {
      enable = true;
      displayManager = {
        gdm = {
          enable = true;
          autoSuspend = false;
        };
        autoLogin = {
          enable = true;
          user = "max";
        };
      };
      desktopManager = {
        gnome = {
          enable = true;
        };
      };
      layout = "gb";
    };
  };
  system = {
    stateVersion = "24.05";
  };
  users = {
    users = {
      max = {
        shell = pkgs.fish;
        password = "nixos";
        isNormalUser = true;
        extraGroups = [ "libvirt" "wheel" ];
      };
    };
  };
  virtualisation = {
    libvirtd = {
      enable = true;
    };
    vmVariant = {
      virtualisation = {
        diskImage = "$HOME/net-lab.qcow2";
        diskSize = (64 * 1024);
        qemu = {
          options = [
            "-vga virtio"
            "-full-screen"
            "-display gtk,grab-on-hover=yes,full-screen=yes"
            "-smp \"$(nproc)\""
            "-m \"$((\"$(getconf _PHYS_PAGES)\" * \"$(getconf PAGE_SIZE)\" / (2 * 1024 * 1024)))\""
            "-accel kvm"
          ];
        };
        resolution = {
          x = 1920;
          y = 1080;
        };
      };
    };
  };
}
