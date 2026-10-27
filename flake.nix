{
  description = "IFClite artifacts and an authenticated local OCI registry in one Rust binary";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      packageFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.rustPlatform.buildRustPackage {
          pname = "ifcx-oci";
          version = "0.2.0";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let
                relative = pkgs.lib.removePrefix ((toString ./.) + "/") (toString path);
              in (toString path) == (toString ./.) || builtins.elem relative [ "Cargo.toml" "Cargo.lock" "LICENSE" "src" "tests" ]
                 || pkgs.lib.hasPrefix "src/" relative || pkgs.lib.hasPrefix "tests/" relative;
          };
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."ifc-lite-core-25.0.0" = "sha256-TtBp7dY9Nu4zsVUl3ZmH5BAIF4+xF6ZsP6n81/oMJHQ=";
          };
          nativeBuildInputs = [ pkgs.pkg-config ];
          # Networked integration tests run explicitly through the demo app.
          cargoTestFlags = [ "--lib" ];
          meta.mainProgram = "ifcx-oci";
          meta.license = pkgs.lib.licenses.asl20;
        };
    in {
      packages = eachSystem (system: { default = packageFor system; });
      apps = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          package = packageFor system;
          demo = pkgs.writeShellScriptBin "ifcx-showcase" ''
            exec ${package}/bin/ifcx-oci demo --oras ${pkgs.oras}/bin/oras "$@"
          '';
        in {
          default = { type = "app"; program = "${package}/bin/ifcx-oci"; meta.description = "IFC artifacts and a scoped local OCI registry"; };
          demo = { type = "app"; program = "${demo}/bin/ifcx-showcase"; meta.description = "Authenticated two-registry showcase with ORAS"; };
        });
      devShells = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc rustfmt clippy pkg-config oras jq ];
        }; });
      checks = eachSystem (system: { build = packageFor system; });
    };
}
