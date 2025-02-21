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

xpub_1_m :: BS.ByteString
xpub_1_m = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

xprv_1_m :: BS.ByteString
xprv_1_m = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

xpub_1_m_0' :: BS.ByteString
xpub_1_m_0' = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

xprv_1_m_0' :: BS.ByteString
xprv_1_m_0' = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

xpub_1_m_0'_1 :: BS.ByteString
xpub_1_m_0'_1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

xprv_1_m_0'_1 :: BS.ByteString
xprv_1_m_0'_1 = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"

xpub_1_m_0'_1_2' :: BS.ByteString
xpub_1_m_0'_1_2' = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

xprv_1_m_0'_1_2' :: BS.ByteString
xprv_1_m_0'_1_2' = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"

xpub_1_m_0'_1_2'_2 :: BS.ByteString
xpub_1_m_0'_1_2'_2 = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

xprv_1_m_0'_1_2'_2 :: BS.ByteString
xprv_1_m_0'_1_2'_2 = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"

xpub_1_m_0'_1_2'_2_1000000000 :: BS.ByteString
xpub_1_m_0'_1_2'_2_1000000000 = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"

xprv_1_m_0'_1_2'_2_1000000000 :: BS.ByteString
xprv_1_m_0'_1_2'_2_1000000000 = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

vector_1 :: TestTree
vector_1 = H.testCase "seed 1" $ do
  let Just _m = master seed_1
  H.assertEqual "M" xpub_1_m (xpub _m)
  H.assertEqual "m" xprv_1_m (xprv _m)
  let Just _m_0' = derive_priv _m 0x80000000
  H.assertEqual "M/0'" xpub_1_m_0' (xpub _m_0')
  H.assertEqual "m/0'" xprv_1_m_0' (xprv _m_0')
  let Just _m_0'_1 = derive_priv _m_0' 1
  H.assertEqual "M/0'/1" xpub_1_m_0'_1 (xpub _m_0'_1)
  H.assertEqual "m/0'/1" xprv_1_m_0'_1 (xprv _m_0'_1)
  let Just _m_0'_1_2' = derive_priv _m_0'_1 (0x80000000 + 2)
  H.assertEqual "M/0'/1/2'" xpub_1_m_0'_1_2' (xpub _m_0'_1_2')
  H.assertEqual "m/0'/1/2'" xprv_1_m_0'_1_2' (xprv _m_0'_1_2')
  let Just _m_0'_1_2'_2 = derive_priv _m_0'_1_2' 2
  H.assertEqual "M/0'/1/2'/2" xpub_1_m_0'_1_2'_2 (xpub _m_0'_1_2'_2)
  H.assertEqual "m/0'/1/2'/2" xprv_1_m_0'_1_2'_2 (xprv _m_0'_1_2'_2)
  let Just _m_0'_1_2'_2_1000000000 = derive_priv _m_0'_1_2'_2 1000000000
  H.assertEqual "M/0'/1/2'/2/1000000000" xpub_1_m_0'_1_2'_2_1000000000
    (xpub _m_0'_1_2'_2_1000000000)
  H.assertEqual "m/0'/1/2'/2/1000000000" xprv_1_m_0'_1_2'_2_1000000000
    (xprv _m_0'_1_2'_2_1000000000)

