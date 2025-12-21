{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Criterion.Main
import Crypto.HDKey.BIP32
import Control.DeepSeq
import Crypto.Curve.Secp256k1 as S
import qualified Data.Maybe as M
import qualified Data.Word.Wider as W

instance NFData S.Projective
instance NFData (X W.Wider)
instance NFData (X S.Projective)
instance NFData XPub
instance NFData XPrv
instance NFData HDKey

main :: IO ()
main = defaultMain [
    bgroup "ppad-bip32" [
        bench_master
      , bench_derive_pub
      , bench_derive_priv
      , bench_xpub
      , bench_xprv
      , bench_parse
    ]
  ]

m :: HDKey
m = case master "my super entropic entropy" of
  Just !s -> s
  _ -> error "bang"

bench_master :: Benchmark
bench_master = bench "master" $ nf master "my super entropic entropy"

bench_derive_pub :: Benchmark
bench_derive_pub = bench "derive_child_pub" $ nf (derive_child_pub m) 0

bench_derive_priv :: Benchmark
bench_derive_priv = bench "derive_child_priv" $ nf (derive_child_priv m) 0

bench_xpub :: Benchmark
bench_xpub = bench "xpub" $ nf xpub m

bench_xprv :: Benchmark
bench_xprv = bench "xprv" $ nf xprv m

bench_parse :: Benchmark
bench_parse = bench "parse" $ nf parse (M.fromJust (xprv m))

