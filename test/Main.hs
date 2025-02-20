{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.HDKey.BIP32
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import qualified Test.Tasty.HUnit as H

main :: IO ()
main = defaultMain vector_1

seed_1 :: BS.ByteString
seed_1 = case B16.decode "000102030405060708090a0b0c0d0e0f" of
  Nothing -> error "bang"
  Just b -> b

xpub_1_M :: BS.ByteString
xpub_1_M = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

xprv_1_m :: BS.ByteString
xprv_1_m = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

xpub_1_M_0' :: BS.ByteString
xpub_1_M_0' = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

xprv_1_m_0' :: BS.ByteString
xprv_1_m_0' = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

vector_1 :: TestTree
vector_1 = H.testCase "seed 1" $ do
  let Just _m = master_priv seed_1
      Just _M = master_pub seed_1
  H.assertEqual "m matches" xprv_1_m (serialize_mainnet _m)
  H.assertEqual "M matches" xpub_1_M (serialize_mainnet _M)
  let Just _m_0' = derive_priv _m (2 ^ 31 + 0)
      Just _M_0' = derive_pub _M (2 ^ 31 + 0)
  H.assertEqual "m/0' matches" xprv_1_m_0' (serialize_mainnet _m_0')
  H.assertEqual "M/0' matches" xpub_1_M_0' (serialize_mainnet _m_0')

