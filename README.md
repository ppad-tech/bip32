# bip32

[![](https://img.shields.io/hackage/v/ppad-bip32?color=blue)](https://hackage.haskell.org/package/ppad-bip32)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-bip32-lightblue)](https://docs.ppad.tech/bip32)

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
  > let Just child = derive m "m/44'/0'/0'/0/0"
  > xpub child
  "xpub6GEwJiJFou5PH6LL8cagArvArrXhSaq35XWnT73CShNRBJa9jxHsWnPsydvmN2vcPBg9KHfRyYLiYnUKCJ8ncba4CgzF56n4kpkqMTSFy35"
  >
  > -- use the 'hd_key' record to extract the extended key
  > let Right my_xprv = hd_key child
  > xprv_key my_xprv
  82064013501759548583899633460204676801585795402966146917762774758050650403971
  >
  > -- use 'parse' to import an extended key
  > let Just hd = xprv child >>= parse
  > hd == child
  True
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/bip32](https://docs.ppad.tech/bip32).

## Performance

The aim is best-in-class performance for pure Haskell code. Most time
is spent on elliptic curve multiplication or hashing; strict BIP32
functionality is only a small layer on top of that.

Current benchmark figures on an M4 Silicon MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-bip32 (wNAF)/derive_child_pub'
  time                 207.4 μs   (207.3 μs .. 207.5 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 207.8 μs   (207.7 μs .. 207.9 μs)
  std dev              419.0 ns   (323.2 ns .. 586.1 ns)

  benchmarking ppad-bip32 (wNAF)/derive_child_priv'
  time                 177.6 μs   (177.4 μs .. 178.0 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 178.6 μs   (178.3 μs .. 178.8 μs)
  std dev              878.1 ns   (741.3 ns .. 1.011 μs)

  benchmarking ppad-bip32/xpub
  time                 145.1 μs   (145.0 μs .. 145.1 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 145.1 μs   (145.1 μs .. 145.2 μs)
  std dev              289.5 ns   (214.5 ns .. 400.7 ns)

  benchmarking ppad-bip32/xprv
  time                 5.715 μs   (5.710 μs .. 5.721 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 5.712 μs   (5.708 μs .. 5.717 μs)
  std dev              14.72 ns   (11.74 ns .. 20.46 ns)

  benchmarking ppad-bip32/parse
  time                 5.868 μs   (5.864 μs .. 5.873 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 5.876 μs   (5.871 μs .. 5.894 μs)
  std dev              28.21 ns   (8.622 ns .. 56.93 ns)
```

You should compile with the 'llvm' flag (and ensure [ppad-fixed][fixed],
[ppad-sha256][sha256], [ppad-sha512][sha512], and [ppad-secp256k1][secp]
are compiled with the 'llvm' flag) for maximum performance.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The implementation within passes the official [BIP32 test
vectors](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#
test-vectors), and all derivations involving secret keys execute in
constant time, and with constant allocation -- see the "Security" notes
in the README of [ppad-secp256k1][secp] for more details.

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
