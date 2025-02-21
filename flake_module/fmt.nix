{ inputs, ... }:
{
  perSystem =
    {
      config,
      ...
    }:
    {
      treefmt.config = {
        inherit (config.flake-root) projectRootFile;
        programs = {
          actionlint.enable = true;
          biome.enable = true;
          mdformat.enable = true;
          nixfmt.enable = true;
          ruff.enable = true;
          rustfmt.enable = true;
          shellcheck.enable = true;
          taplo.enable = true;

        };
      };
    };
}
