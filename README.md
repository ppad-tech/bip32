# bip32

[![](https://img.shields.io/hackage/v/ppad-bip32?color=blue)](https://hackage.haskell.org/package/ppad-bip32)
![](https://img.shields.io/badge/license-MIT-brightgreen)

An implementation of [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) hierarchical deterministic wallets and extended keys.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > import Crypto.HDKey.BIP32
  >
  > -- derive a master node from a master seed
  > let Just m = master "plenty of entropy"
  >
  > -- use 'xpub', 'xprv', etc. to serialize
  > xpub m
  "xpub661MyMwAqRbcG6TPJvVs1yKFJGtN4vi785g2xDacQ9Luyw3gyAyvY5DNatPzfsUQK4nTUAmQboxw3WYDHtY4vfcGJR4FAuLLaUp2t7ejhoC"
  >
  > -- derive child nodes via a path
  > let child = derive_partial m "m/44'/0'/0'/0/0"
  > xpub child
  "xpub6GEwJiJFou5PH6LL8cagArvArrXhSaq35XWnT73CShNRBJa9jxHsWnPsydvmN2vcPBg9KHfRyYLiYnUKCJ8ncba4CgzF56n4kpkqMTSFy35"
  >
  > -- use the 'hd_key' record to extract the extended key
  > let Right (XPrv (X sec cod)) = hd_key child
  > sec
  82064013501759548583899633460204676801585795402966146917762774758050650403971
  >
  > -- use 'parse' to import an extended key
  > let Just hd = parse (xprv child)
  > hd == child
  True
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/bip32](https://docs.ppad.tech/bip32).

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The implementation within passes the official [BIP32 test
vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors), and all derivations involving secret keys execute
*algorithmically* in constant time -- see the "Security" notes in the
README of [ppad-secp256k1][secp] for more details.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-bip32
```

to get a REPL for the main library.

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[const]: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
[secp]: https://git.ppad.tech/secp256k1
