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

## Performance

The aim is best-in-class performance for pure, highly-auditable Haskell
code. Most time is spent on elliptic curve multiplication or hashing;
strict BIP32 functionality is only a small layer on top of that.

Current benchmark figures on my mid-2020 MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-bip32/derive_child_pub
  time                 7.766 ms   (7.404 ms .. 8.215 ms)
                       0.985 R²   (0.975 R² .. 0.995 R²)
  mean                 7.717 ms   (7.565 ms .. 7.890 ms)
  std dev              463.5 μs   (362.7 μs .. 653.5 μs)
  variance introduced by outliers: 31% (moderately inflated)

  benchmarking ppad-bip32/derive_child_priv
  time                 5.080 ms   (4.884 ms .. 5.277 ms)
                       0.991 R²   (0.985 R² .. 0.997 R²)
  mean                 5.045 ms   (4.974 ms .. 5.140 ms)
  std dev              252.6 μs   (201.1 μs .. 310.9 μs)
  variance introduced by outliers: 28% (moderately inflated)

  benchmarking ppad-bip32/xpub
  time                 2.654 ms   (2.571 ms .. 2.771 ms)
                       0.984 R²   (0.976 R² .. 0.992 R²)
  mean                 2.613 ms   (2.538 ms .. 2.684 ms)
  std dev              242.8 μs   (204.0 μs .. 284.3 μs)
  variance introduced by outliers: 64% (severely inflated)

  benchmarking ppad-bip32/xprv
  time                 28.10 μs   (25.95 μs .. 30.39 μs)
                       0.949 R²   (0.910 R² .. 0.987 R²)
  mean                 27.39 μs   (25.84 μs .. 30.17 μs)
  std dev              6.442 μs   (3.813 μs .. 10.21 μs)
  variance introduced by outliers: 97% (severely inflated)

  benchmarking ppad-bip32/parse
  time                 33.20 μs   (31.98 μs .. 34.31 μs)
                       0.993 R²   (0.989 R² .. 0.997 R²)
  mean                 32.89 μs   (32.08 μs .. 33.81 μs)
  std dev              2.958 μs   (2.300 μs .. 3.970 μs)
  variance introduced by outliers: 81% (severely inflated)
```

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
