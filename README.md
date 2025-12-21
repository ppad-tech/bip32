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
  time                 184.0 μs   (183.9 μs .. 184.2 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 184.2 μs   (184.1 μs .. 184.4 μs)
  std dev              502.2 ns   (282.7 ns .. 986.8 ns)

  benchmarking ppad-bip32 (wNAF)/derive_child_priv'
  time                 170.4 μs   (170.3 μs .. 170.6 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 170.6 μs   (170.5 μs .. 170.7 μs)
  std dev              430.8 ns   (314.5 ns .. 600.4 ns)

  benchmarking ppad-bip32/xpub
  time                 151.4 μs   (151.2 μs .. 151.6 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 151.1 μs   (150.9 μs .. 151.3 μs)
  std dev              608.5 ns   (449.2 ns .. 919.9 ns)

  benchmarking ppad-bip32/xprv
  time                 8.374 μs   (8.363 μs .. 8.386 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 8.390 μs   (8.379 μs .. 8.409 μs)
  std dev              47.10 ns   (31.45 ns .. 76.90 ns)

  benchmarking ppad-bip32/parse
  time                 8.576 μs   (8.573 μs .. 8.580 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 8.567 μs   (8.559 μs .. 8.574 μs)
  std dev              25.37 ns   (21.07 ns .. 30.30 ns)
```

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
