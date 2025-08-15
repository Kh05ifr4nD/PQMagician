{
  inputs = {
    flake-parts = {
      inputs.nixpkgs-lib.follows = "nixpkgs";
      url = "github:hercules-ci/flake-parts";
    };
    flake-root.url = "github:srid/flake-root";
    git-hooks-nix.url = "github:cachix/pre-commit-hooks.nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    systems.url = "github:nix-systems/default";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };
  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports =
        with inputs;
        [
          flake-root.flakeModule
          git-hooks-nix.flakeModule
          treefmt-nix.flakeModule
        ]
        ++ (with builtins; map (f: ./flake_module/${f}) (attrNames (readDir ./flake_module)));
      systems = import inputs.systems;
    };
}
