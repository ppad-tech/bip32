{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.HDKey.BIP32
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import qualified Test.Tasty.HUnit as H

main :: IO ()
main = defaultMain $ testGroup "BIP32 vectors" [
    vector_1
  , vector_2
  , vector_3
  , vector_4
  , vector_5
  ]

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
vector_1 = H.testCase "BIP32 vector 1" $ do
  let Just _m = master seed_1
  H.assertEqual "M" xpub_1_m (xpub _m)
  H.assertEqual "m" xprv_1_m (xprv _m)
  let Just _m_0' = derive_child_priv _m 0x80000000
  H.assertEqual "M/0'" xpub_1_m_0' (xpub _m_0')
  H.assertEqual "m/0'" xprv_1_m_0' (xprv _m_0')
  H.assertEqual "M/0', path" xpub_1_m_0' (xpub (derive_partial _m "m/0'"))
  H.assertEqual "m/0', path" xprv_1_m_0' (xprv (derive_partial _m "m/0'"))
  let Just _m_0'_1 = derive_child_priv _m_0' 1
  H.assertEqual "M/0'/1" xpub_1_m_0'_1 (xpub _m_0'_1)
  H.assertEqual "m/0'/1" xprv_1_m_0'_1 (xprv _m_0'_1)
  H.assertEqual "M/0'/1" xpub_1_m_0'_1 (xpub (derive_partial _m "m/0'/1"))
  H.assertEqual "m/0'/1" xprv_1_m_0'_1 (xprv (derive_partial _m "m/0'/1"))
  let Just _m_0'_1_2' = derive_child_priv _m_0'_1 (0x80000000 + 2)
  H.assertEqual "M/0'/1/2'" xpub_1_m_0'_1_2' (xpub _m_0'_1_2')
  H.assertEqual "m/0'/1/2'" xprv_1_m_0'_1_2' (xprv _m_0'_1_2')
  H.assertEqual "M/0'/1/2'" xpub_1_m_0'_1_2' (xpub (derive_partial _m "m/0'/1/2'"))
  H.assertEqual "m/0'/1/2'" xprv_1_m_0'_1_2' (xprv (derive_partial _m "m/0'/1/2'"))
  let Just _m_0'_1_2'_2 = derive_child_priv _m_0'_1_2' 2
  H.assertEqual "M/0'/1/2'/2" xpub_1_m_0'_1_2'_2 (xpub _m_0'_1_2'_2)
  H.assertEqual "m/0'/1/2'/2" xprv_1_m_0'_1_2'_2 (xprv _m_0'_1_2'_2)
  H.assertEqual "M/0'/1/2'/2" xpub_1_m_0'_1_2'_2
    (xpub (derive_partial _m "m/0'/1/2'/2"))
  H.assertEqual "m/0'/1/2'/2" xprv_1_m_0'_1_2'_2
    (xprv (derive_partial _m "m/0'/1/2'/2"))
  let Just _m_0'_1_2'_2_1000000000 = derive_child_priv _m_0'_1_2'_2 1000000000
  H.assertEqual "M/0'/1/2'/2/1000000000" xpub_1_m_0'_1_2'_2_1000000000
    (xpub _m_0'_1_2'_2_1000000000)
  H.assertEqual "m/0'/1/2'/2/1000000000" xprv_1_m_0'_1_2'_2_1000000000
    (xprv _m_0'_1_2'_2_1000000000)
  H.assertEqual "M/0'/1/2'/2/1000000000" xpub_1_m_0'_1_2'_2_1000000000
    (xpub (derive_partial _m "m/0'/1/2'/2/1000000000"))
  H.assertEqual "m/0'/1/2'/2/1000000000" xprv_1_m_0'_1_2'_2_1000000000
    (xprv (derive_partial _m "m/0'/1/2'/2/1000000000"))

seed_2 :: BS.ByteString
seed_2 = case B16.decode "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542" of
  Nothing -> error "bang"
  Just b -> b

vector_2 :: TestTree
vector_2 = H.testCase "BIP32 vector 2" $ do
  let Just mas = master seed_2
      _m = derive_partial mas "m"
  H.assertEqual "M" "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    (xpub _m)
  H.assertEqual "m" "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    (xprv _m)
  let _m_0 = derive_partial mas "m/0"
  H.assertEqual "M/0" "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    (xpub _m_0)
  H.assertEqual "m/0" "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    (xprv _m_0)
  let _m_0_2147483647' = derive_partial mas "m/0/2147483647'"
  H.assertEqual "M/0/2147483647'" "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
    (xpub _m_0_2147483647')
  H.assertEqual "m/0/2147483647'" "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    (xprv _m_0_2147483647')
  let _m_0_2147483647'_1 = derive_partial mas "m/0/2147483647'/1"
  H.assertEqual "M/0/2147483647'/1" "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
    (xpub _m_0_2147483647'_1)
  H.assertEqual "m/0/2147483647'/1" "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    (xprv _m_0_2147483647'_1)
  let _m_0_2147483647'_1_2147483646' =
        derive_partial mas "m/0/2147483647'/1/2147483646'"
  H.assertEqual "M/0/2147483647'/1/2147483646'" "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    (xpub _m_0_2147483647'_1_2147483646')
  H.assertEqual "m/0/2147483647'/1/2147483646'" "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
    (xprv _m_0_2147483647'_1_2147483646')
  let _m_0_2147483647'_1_2147483646'_2 =
        derive_partial mas "m/0/2147483647'/1/2147483646'/2"
  H.assertEqual "M/0/2147483647'/1/2147483646'/2" "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
    (xpub _m_0_2147483647'_1_2147483646'_2)
  H.assertEqual "m/0/2147483647'/1/2147483646'/2" "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    (xprv _m_0_2147483647'_1_2147483646'_2)

seed_3 :: BS.ByteString
seed_3 = case B16.decode "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be" of
  Nothing -> error "bang"
  Just b -> b

vector_3 :: TestTree
vector_3 = H.testCase "BIP32 vector 3" $ do
  let Just mas = master seed_3
      _m = derive_partial mas "m"
  H.assertEqual "M" "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
    (xpub _m)
  H.assertEqual "m" "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    (xprv _m)
  let _m_0' = derive_partial mas "m/0'"
  H.assertEqual "M/0'" "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    (xpub _m_0')
  H.assertEqual "m/0'" "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    (xprv _m_0')

seed_4 :: BS.ByteString
seed_4 = case B16.decode "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678" of
  Nothing -> error "bang"
  Just b -> b

vector_4 :: TestTree
vector_4 = H.testCase "BIP32 vector 4" $ do
  let Just mas = master seed_4
      _m = derive_partial mas "m"
  H.assertEqual "M" "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
    (xpub _m)
  H.assertEqual "m" "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    (xprv _m)
  let _m_0' = derive_partial mas "m/0'"
  H.assertEqual "M/0'" "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
    (xpub _m_0')
  H.assertEqual "m/0'" "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    (xprv _m_0')
  let _m_0'_1' = derive_partial mas "m/0'/1'"
  H.assertEqual "M/0'/1'" "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
    (xpub _m_0'_1')
  H.assertEqual "m/0'/1'" "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    (xprv _m_0'_1')

vector_5 :: TestTree
vector_5 = H.testCase "BIP32 vector 5" $ do
  H.assertEqual "k0" Nothing (parse "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm")
  H.assertEqual "k1" Nothing (parse "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH")
  H.assertEqual "k2" Nothing (parse "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn")
  H.assertEqual "k3" Nothing (parse "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ")
  H.assertEqual "k4" Nothing (parse "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4")
  H.assertEqual "k5" Nothing (parse "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J")
  H.assertEqual "k6" Nothing (parse "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv")
  H.assertEqual "k7" Nothing (parse "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ")
  H.assertEqual "k8" Nothing (parse "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN")
  H.assertEqual "k9" Nothing (parse "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8")
  H.assertEqual "k10" Nothing (parse "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4")
  H.assertEqual "k11" Nothing (parse "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9")
  H.assertEqual "k12" Nothing (parse "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx")
  H.assertEqual "k13" Nothing (parse "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G")
  H.assertEqual "k14" Nothing (parse "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY")
  H.assertEqual "k15" Nothing (parse "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL")


