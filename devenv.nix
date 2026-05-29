{
  pkgs,
  lib,
  inputs,
  ...
}:

{
  packages =
    with pkgs;
    [
      lld
      cargo-audit
      cargo-deny
      cargo-dist
      cargo-release
      cargo-watch
      dioxus-cli
      (callPackage ./nix/wasm-bindgen-cli.nix { version = "0.2.122"; })
    ]
    ++ lib.optionals stdenv.isLinux [
      pkg-config
      glib
      gtk3
      webkitgtk_4_1
    ];

  overlays = [
    (
      final: prev:
      let
        pkgs = inputs.nixpkgsUnstable.legacyPackages.${final.stdenv.system};
      in
      {
        dioxus-cli = pkgs.dioxus-cli;
      }
    )
  ];

  languages = {
    rust = {
      enable = true;
      channel = "stable";
      targets = [ "wasm32-unknown-unknown" ];
    };

    javascript = {
      enable = true;
      bun.enable = true;
    };
  };
}
