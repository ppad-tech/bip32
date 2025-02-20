{
  description = "Pure Haskell BIP32 hierarchical deterministic wallets.";

  inputs = {
    ppad-nixpkgs = {
      type = "git";
      url  = "git://git.ppad.tech/nixpkgs.git";
      ref  = "master";
    };
    ppad-base16 = {
      type = "git";
      url  = "git://git.ppad.tech/base16.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
      inputs.ppad-sha256.follows = "ppad-sha256";
    };
    ppad-base58 = {
      type = "git";
      url  = "git://git.ppad.tech/base58.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
      inputs.ppad-sha256.follows = "ppad-sha256";
    };
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-sha512 = {
      type = "git";
      url  = "git://git.ppad.tech/sha512.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-ripemd160 = {
      type = "git";
      url  = "git://git.ppad.tech/ripemd160.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-secp256k1 = {
      type = "git";
      url  = "git://git.ppad.tech/secp256k1.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
      inputs.ppad-sha256.follows = "ppad-sha256";
      inputs.ppad-sha512.follows = "ppad-sha512";
    };
    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-sha256, ppad-sha512, ppad-ripemd160
            , ppad-base16, ppad-base58
            , ppad-secp256k1 }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-bip32";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ${lib} = old.callCabal2nixWithOptions lib ./. "--enable-profiling" {};
          ppad-sha256 = ppad-sha256.packages.${system}.default;
          ppad-sha512 = ppad-sha512.packages.${system}.default;
          ppad-ripemd160 = ppad-ripemd160.packages.${system}.default;
          ppad-base16 = ppad-base16.packages.${system}.default;
          ppad-base58 = ppad-base58.packages.${system}.default;
          ppad-secp256k1 = ppad-secp256k1.packages.${system}.default;
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

