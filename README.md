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

The aim is best-in-class performance for pure, highly-auditable Haskell
code. Most time is spent on elliptic curve multiplication or hashing;
strict BIP32 functionality is only a small layer on top of that.

Current benchmark figures on an M4 Silicon MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-bip32/derive_child_pub
  time                 2.668 ms   (2.663 ms .. 2.672 ms)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 2.661 ms   (2.658 ms .. 2.664 ms)
  std dev              8.440 μs   (6.211 μs .. 13.00 μs)

  benchmarking ppad-bip32/derive_child_priv
  time                 1.784 ms   (1.783 ms .. 1.785 ms)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.781 ms   (1.780 ms .. 1.782 ms)
  std dev              2.300 μs   (1.939 μs .. 2.835 μs)

  benchmarking ppad-bip32/xpub
  time                 901.1 μs   (900.0 μs .. 902.3 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 900.3 μs   (899.7 μs .. 901.7 μs)
  std dev              3.053 μs   (1.724 μs .. 5.362 μs)

  benchmarking ppad-bip32/xprv
  time                 8.665 μs   (8.656 μs .. 8.673 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 8.667 μs   (8.663 μs .. 8.670 μs)
  std dev              12.75 ns   (9.805 ns .. 17.26 ns)

  benchmarking ppad-bip32/parse
  time                 9.295 μs   (9.273 μs .. 9.330 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 9.294 μs   (9.288 μs .. 9.308 μs)
  std dev              27.58 ns   (11.06 ns .. 55.76 ns)
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
