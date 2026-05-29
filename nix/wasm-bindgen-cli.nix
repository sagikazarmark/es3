{
  lib,
  stdenvNoCC,
  fetchurl,
  version ? "0.2.122",
}:

let
  releases = import ./wasm-bindgen-cli-versions.nix;

  release =
    releases.${version}
      or (throw "wasm-bindgen-cli ${version} is not packaged; known versions: ${lib.concatStringsSep ", " (builtins.attrNames releases)}");

  source =
    release.${stdenvNoCC.hostPlatform.system}
      or (throw "wasm-bindgen-cli ${version} is not available for ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "wasm-bindgen-cli";
  inherit version;

  src = fetchurl {
    inherit (source) url hash;
  };

  sourceRoot = "wasm-bindgen-${version}-${source.target}";

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/bin"
    install -m755 wasm-bindgen "$out/bin/wasm-bindgen"
    install -m755 wasm-bindgen-test-runner "$out/bin/wasm-bindgen-test-runner"
    install -m755 wasm2es6js "$out/bin/wasm2es6js"

    runHook postInstall
  '';

  meta = {
    description = "Facilitating high-level interactions between Wasm modules and JavaScript";
    homepage = "https://github.com/wasm-bindgen/wasm-bindgen";
    license = with lib.licenses; [
      asl20
      mit
    ];
    mainProgram = "wasm-bindgen";
    platforms = builtins.attrNames release;
    sourceProvenance = with lib.sourceTypes; [ binaryNativeCode ];
  };
}
