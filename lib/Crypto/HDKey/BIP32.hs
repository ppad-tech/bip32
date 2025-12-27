{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.HDKey.BIP32
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
-- hierarchical deterministic wallets and extended keys, with support for
-- serialization and parsing.

module Crypto.HDKey.BIP32 (
  -- * Hierarchical deterministic keys
    HDKey(..)
  , master

  -- * Extended keys
  , Extended(..)
  , XPub
  , xpub_key
  , xpub_cod
  , XPrv
  , xprv_key
  , xprv_cod
  , X
  , ckd_pub
  , ckd_priv
  , n

  -- * Child derivation via path
  , derive
  , derive_partial

  -- * Serialization
  , xpub
  , xprv
  , tpub
  , tprv

  -- * Parsing
  , parse

  -- * Child key derivation functions
  , derive_child_pub
  , derive_child_priv

  -- * Fast wNAF variants
  , Context
  , precompute
  , ckd_priv'
  , ckd_pub'
  , n'
  , derive'
  , derive_partial'
  , derive_child_priv'
  , derive_child_pub'
  ) where

import Control.Monad (guard)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Data.Bits ((.>>.), (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base58Check as B58C
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Choice as C
import Data.Word (Word8, Word32)
import Data.Word.Limb (Limb(..))
import qualified Data.Word.Limb as L
import Data.Word.Wider (Wider(..))
import qualified Data.Word.Wider as W
import qualified Foreign.Storable as Storable (pokeByteOff)
import qualified GHC.Exts as Exts
import GHC.Generics
import qualified GHC.Word (Word8(..))
import qualified Numeric.Montgomery.Secp256k1.Scalar as S

-- | Precomputed multiples of the secp256k1 generator point, for faster
--   scalar multiplication.
type Context = Secp256k1.Context

-- | Create a secp256k1 context by precomputing multiples of the curve's
--   generator point.
--
--   This should be computed once and reused for all derivations.
--
--   >>> let !ctx = precompute
--   >>> derive' ctx hd "m/44'/0'/0'/0/0"
precompute :: Context
precompute = Secp256k1.precompute

-- parsing utilities ----------------------------------------------------------

-- convert a Word8 to a Limb
limb :: Word8 -> Limb
limb (GHC.Word.W8# (Exts.word8ToWord# -> w)) = Limb w
{-# INLINABLE limb #-}

-- convert a Limb to a Word8
word8 :: Limb -> Word8
word8 (Limb w) = GHC.Word.W8# (Exts.wordToWord8# w)
{-# INLINABLE word8 #-}

-- unsafely extract the first 64-bit word from a big-endian-encoded bytestring
unsafe_word0 :: BS.ByteString -> Limb
unsafe_word0 bs =
          (limb (BU.unsafeIndex bs 00) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 01) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 02) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 03) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 04) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 05) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 06) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 07))
{-# INLINABLE unsafe_word0 #-}

-- unsafely extract the second 64-bit word from a big-endian-encoded bytestring
unsafe_word1 :: BS.ByteString -> Limb
unsafe_word1 bs =
          (limb (BU.unsafeIndex bs 08) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 09) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 10) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 11) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 12) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 13) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 14) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 15))
{-# INLINABLE unsafe_word1 #-}

-- unsafely extract the third 64-bit word from a big-endian-encoded bytestring
unsafe_word2 :: BS.ByteString -> Limb
unsafe_word2 bs =
          (limb (BU.unsafeIndex bs 16) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 17) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 18) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 19) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 20) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 21) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 22) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 23))
{-# INLINABLE unsafe_word2 #-}

-- unsafely extract the fourth 64-bit word from a big-endian-encoded bytestring
unsafe_word3 :: BS.ByteString -> Limb
unsafe_word3 bs =
          (limb (BU.unsafeIndex bs 24) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 25) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 26) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 27) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 28) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 29) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 30) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 31))
{-# INLINABLE unsafe_word3 #-}

-- 256-bit big-endian bytestring decoding. the input size is not checked!
unsafe_roll32 :: BS.ByteString -> Wider
unsafe_roll32 bs =
  let !w0 = unsafe_word0 bs
      !w1 = unsafe_word1 bs
      !w2 = unsafe_word2 bs
      !w3 = unsafe_word3 bs
  in  Wider (# w3, w2, w1, w0 #)
{-# INLINABLE unsafe_roll32 #-}

-- convert a Limb to a Word8 after right-shifting
word8s :: Limb -> Exts.Int# -> Word8
word8s l s =
  let !(Limb w) = L.shr# l s
  in  GHC.Word.W8# (Exts.wordToWord8# w)
{-# INLINABLE word8s #-}

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- 256-bit big-endian bytestring encoding
unroll32 :: Wider -> BS.ByteString
unroll32 (Wider (# w0, w1, w2, w3 #)) =
  BI.unsafeCreate 32 $ \ptr -> do
    -- w0
    Storable.pokeByteOff ptr 00 (word8s w3 56#)
    Storable.pokeByteOff ptr 01 (word8s w3 48#)
    Storable.pokeByteOff ptr 02 (word8s w3 40#)
    Storable.pokeByteOff ptr 03 (word8s w3 32#)
    Storable.pokeByteOff ptr 04 (word8s w3 24#)
    Storable.pokeByteOff ptr 05 (word8s w3 16#)
    Storable.pokeByteOff ptr 06 (word8s w3 08#)
    Storable.pokeByteOff ptr 07 (word8 w3)
    -- w1
    Storable.pokeByteOff ptr 08 (word8s w2 56#)
    Storable.pokeByteOff ptr 09 (word8s w2 48#)
    Storable.pokeByteOff ptr 10 (word8s w2 40#)
    Storable.pokeByteOff ptr 11 (word8s w2 32#)
    Storable.pokeByteOff ptr 12 (word8s w2 24#)
    Storable.pokeByteOff ptr 13 (word8s w2 16#)
    Storable.pokeByteOff ptr 14 (word8s w2 08#)
    Storable.pokeByteOff ptr 15 (word8 w2)
    -- w2
    Storable.pokeByteOff ptr 16 (word8s w1 56#)
    Storable.pokeByteOff ptr 17 (word8s w1 48#)
    Storable.pokeByteOff ptr 18 (word8s w1 40#)
    Storable.pokeByteOff ptr 19 (word8s w1 32#)
    Storable.pokeByteOff ptr 20 (word8s w1 24#)
    Storable.pokeByteOff ptr 21 (word8s w1 16#)
    Storable.pokeByteOff ptr 22 (word8s w1 08#)
    Storable.pokeByteOff ptr 23 (word8 w1)
    -- w3
    Storable.pokeByteOff ptr 24 (word8s w0 56#)
    Storable.pokeByteOff ptr 25 (word8s w0 48#)
    Storable.pokeByteOff ptr 26 (word8s w0 40#)
    Storable.pokeByteOff ptr 27 (word8s w0 32#)
    Storable.pokeByteOff ptr 28 (word8s w0 24#)
    Storable.pokeByteOff ptr 29 (word8s w0 16#)
    Storable.pokeByteOff ptr 30 (word8s w0 08#)
    Storable.pokeByteOff ptr 31 (word8 w0)
{-# INLINABLE unroll32 #-}

-- serialize a 32-bit word, MSB first
ser32 :: Word32 -> BS.ByteString
ser32 w =
  let !mask = 0b00000000_00000000_00000000_11111111
      !w0 = fi (w .>>. 24) .&. mask
      !w1 = fi (w .>>. 16) .&. mask
      !w2 = fi (w .>>. 08) .&. mask
      !w3 = fi w .&. mask
  in  BS.cons w0 (BS.cons w1 (BS.cons w2 (BS.singleton w3)))

-- extended keys --------------------------------------------------------------

-- | An extended public key.
newtype XPub = XPub (X Secp256k1.Projective)
  deriving (Eq, Show, Generic)

-- | Read the raw public key from an 'XPub'.
xpub_key :: XPub -> Secp256k1.Projective
xpub_key (XPub (X pub _)) = pub

-- | Read the raw chain code from an 'XPub'.
xpub_cod :: XPub -> BS.ByteString
xpub_cod (XPub (X _ cod)) = cod

-- | An extended private key.
newtype XPrv = XPrv (X Wider)
  deriving (Show, Generic)

-- | Read the raw private key from an 'XPrv'.
xprv_key :: XPrv -> Wider
xprv_key (XPrv (X sec _)) = sec

-- | Read the raw chain code from an 'XPrv'.
xprv_cod :: XPrv -> BS.ByteString
xprv_cod (XPrv (X _ cod)) = cod

-- | A public or private key, extended with a chain code.
data X a = X !a !BS.ByteString
  deriving (Eq, Show, Generic)

-- | Key types supporting identifier/fingerprint calculation.
--
--   >>> let Just hd = master "my very secret entropy"
--   >>> let Right my_xprv = hd_key hd
--   >>> let my_xpub = n k
--   >>> -- all have the same fingerprint
--   >>> fingerprint hd
--   "G\157\&8\146"
--   >>> fingerprint my_xprv
--   "G\157\&8\146"
--   >>> fingerprint my_xpub
--   "G\157\&8\146"
class Extended k where
  -- | Calculate the identifier for an extended key.
  identifier  :: k -> BS.ByteString

  -- | Calculate the fingerprint of an extended key.
  fingerprint :: k -> BS.ByteString
  fingerprint = BS.take 4 . identifier

instance Extended XPub where
  identifier (XPub (X pub _)) =
    let ser = Secp256k1.serialize_point pub
    in  RIPEMD160.hash (SHA256.hash ser)

instance Extended XPrv where
  identifier (XPrv (X sec _)) = case Secp256k1.mul Secp256k1._CURVE_G sec of
    Nothing ->
      error "ppad-bip32 (identifier): internal error, evil extended key"
    Just p ->
      let ser = Secp256k1.serialize_point p
      in  RIPEMD160.hash (SHA256.hash ser)

-- internal key derivation functions-------------------------------------------

hardened :: Word32 -> Bool
hardened = (>= 0x8000_0000)

-- master xprv from seed
_master :: BS.ByteString -> Maybe XPrv
_master seed@(BI.PS _ _ l)
  | l < 16 = Nothing
  | l > 64 = Nothing
  | otherwise = do
      let i = SHA512.hmac "Bitcoin seed" seed
          (il, c) = BS.splitAt 32 i
          s = unsafe_roll32 il -- safe due to 512-bit hmac
      pure $! (XPrv (X s c))

-- private parent key -> private child key
ckd_priv :: XPrv -> Word32 -> XPrv
ckd_priv _xprv@(XPrv (X sec cod)) i =
    let l = SHA512.hmac cod dat
        (il, ci) = BS.splitAt 32 l
        pil = unsafe_roll32 il -- safe due to 512-bit hmac
        ki  = S.from (S.to pil + S.to sec)
        com = W.cmp_vartime pil Secp256k1._CURVE_Q
    in  if   com /= LT || W.eq_vartime ki 0 -- negl
        then ckd_priv _xprv (succ i)
        else XPrv (X ki ci)
  where
    dat | hardened i = BS.singleton 0x00 <> unroll32 sec <> ser32 i
        | otherwise  = case Secp256k1.mul Secp256k1._CURVE_G sec of
            Nothing ->
              error "ppad-bip32 (ckd_priv): internal error, evil extended key"
            Just p  -> Secp256k1.serialize_point p <> ser32 i

-- public parent key -> public child key
ckd_pub :: XPub -> Word32 -> Maybe XPub
ckd_pub _xpub@(XPub (X pub cod)) i
  | hardened i = Nothing
  | otherwise = do
      let dat = Secp256k1.serialize_point pub <> ser32 i
          l   = SHA512.hmac cod dat
          (il, ci) = BS.splitAt 32 l
          pil = unsafe_roll32 il -- safe due to 512-bit hmac
      pt <- Secp256k1.mul_vartime Secp256k1._CURVE_G pil
      let  ki  = pt `Secp256k1.add` pub
           com = W.cmp_vartime pil Secp256k1._CURVE_Q
      if   com /= LT || ki == Secp256k1._CURVE_ZERO -- negl
      then ckd_pub _xpub (succ i)
      else pure (XPub (X ki ci))

-- private parent key -> public child key
n :: XPrv -> XPub
n (XPrv (X sec cod)) = case Secp256k1.mul Secp256k1._CURVE_G sec of
  Nothing -> error "ppad-bip32 (n): internal error, evil extended key"
  Just p -> XPub (X p cod)

-- fast variants --------------------------------------------------------------

-- | The same as 'ckd_priv', but uses a 'Context' to optimise internal
--   calculations.
ckd_priv' :: Context -> XPrv -> Word32 -> XPrv
ckd_priv' ctx _xprv@(XPrv (X sec cod)) i =
    let l = SHA512.hmac cod dat
        (il, ci) = BS.splitAt 32 l
        pil = unsafe_roll32 il -- safe due to 512-bit hmac
        ki  = S.from (S.to pil + S.to sec)
        com = W.cmp_vartime pil Secp256k1._CURVE_Q
    in  if   com /= LT || W.eq_vartime ki 0 -- negl
        then ckd_priv' ctx _xprv (succ i)
        else XPrv (X ki ci)
  where
    dat | hardened i = BS.singleton 0x00 <> unroll32 sec <> ser32 i
        | otherwise  = case Secp256k1.mul_wnaf ctx sec of
            Nothing ->
              error "ppad-bip32 (ckd_priv'): internal error, evil extended key"
            Just p  -> Secp256k1.serialize_point p <> ser32 i

-- | The same as 'ckd_pub', but uses a 'Context' to optimise internal
--   calculations.
ckd_pub' :: Context -> XPub -> Word32 -> Maybe XPub
ckd_pub' ctx _xpub@(XPub (X pub cod)) i
  | hardened i = Nothing
  | otherwise = do
      let dat = Secp256k1.serialize_point pub <> ser32 i
          l   = SHA512.hmac cod dat
          (il, ci) = BS.splitAt 32 l
          pil = unsafe_roll32 il -- safe due to 512-bit hmac
      pt <- Secp256k1.mul_wnaf ctx pil
      let  ki = pt `Secp256k1.add` pub
           com = W.cmp_vartime pil Secp256k1._CURVE_Q
      if   com /= LT || ki == Secp256k1._CURVE_ZERO -- negl
      then ckd_pub' ctx _xpub (succ i)
      else pure (XPub (X ki ci))

-- | The same as 'n', but uses a 'Context' to optimise internal calculations.
n' :: Context -> XPrv -> XPub
n' ctx (XPrv (X sec cod)) = case Secp256k1.mul_wnaf ctx sec of
  Nothing -> error "ppad-bip32 (n'): internal error, evil extended key"
  Just p -> XPub (X p cod)

-- hierarchical deterministic keys --------------------------------------------

-- | A BIP32 hierarchical deterministic key.
--
--   This differs from lower-level "extended" keys in that it carries all
--   information required for serialization.
data HDKey = HDKey {
    hd_key    :: !(Either XPub XPrv) -- ^ extended public or private key
  , hd_depth  :: !Word8              -- ^ key depth
  , hd_parent :: !BS.ByteString      -- ^ parent fingerprint
  , hd_child  :: !BS.ByteString      -- ^ index or child number
  }
  deriving (Show, Generic)

instance Extended HDKey where
  identifier (HDKey ekey _ _ _) = case ekey of
    Left l -> identifier l
    Right r -> identifier r

-- | Derive a master 'HDKey' from a master seed.
--
--   Fails with 'Nothing' if the provided seed has an invalid length.
--
---  >>> let Just hd = master "my very secret entropy"
--   >>> xpub hd
--   "xpub661MyMwAqRbcGTJPtZRqZyrvjxHCfhqXeiqb5GVU3EGuFBy4QxT3yt8iiHwZTiCzZFyuyNiqXB3eqzqFZ8z4L6HCrPSkDVFNuW59LXYvMjs"
master :: BS.ByteString -> Maybe HDKey
master seed = do
  m <- _master seed
  pure $! HDKey {
      hd_key = Right m
    , hd_depth = 0
    , hd_parent = "\NUL\NUL\NUL\NUL" -- 0x0000_0000
    , hd_child = ser32 0
    }

-- | Derive a private child node at the provided index.
--
--   Fails with 'Nothing' if derivation is impossible.
--
--   >>> let Just child_prv = derive_child_priv hd 0
--   >>> xpub child_prv
--   "xpub68R2ZbtFeJTFJApdEdPqW5cy3d5wF96tTfJErhu3mTi2Ttaqvc88BMPrgS3hQSrHj91kRbzVLM9pue9f8219szRKZuTAx1LWbdLDLFDm6Ly"
derive_child_priv :: HDKey -> Word32 -> Maybe HDKey
derive_child_priv HDKey {..} i = case hd_key of
  Left _ -> Nothing
  Right _xprv -> pure $!
    let key   = Right (ckd_priv _xprv i)
        depth = hd_depth + 1
        parent = fingerprint _xprv
        child = ser32 i
    in  HDKey key depth parent child

-- | Derive a public child node at the provided index.
--
--   Fails with 'Nothing' if derivation is impossible.
--
--   >>> :set -XNumericUnderscores
--   >>> let Just child_pub = derive_child_pub child_prv 0x8000_0000
--   >>> xpub child_pub
--   "xpub6B6LoU83Cpyx1UVMwuoQdQvY2BuGbPd2xsEVxCnj85UGgDN9bRz82hQhe9UFmyo4Pokuhjc8M1Cfc8ufLxcL6FkCF7Zc2eajEfWfZwMFF6X"
derive_child_pub :: HDKey -> Word32 -> Maybe HDKey
derive_child_pub HDKey {..} i = do
  (key, parent) <- case hd_key of
    Left _xpub  -> do
      pub <- ckd_pub _xpub i
      pure $! (pub, fingerprint _xpub)
    Right _xprv ->
      let pub = n (ckd_priv _xprv i)
      in  pure $! (pub, fingerprint _xprv)
  let depth = hd_depth + 1
      child = ser32 i
  pure $! HDKey (Left key) depth parent child

-- | The same as 'derive_child_priv', but uses a 'Context' to optimise
--   internal calculations.
derive_child_priv' :: Context -> HDKey -> Word32 -> Maybe HDKey
derive_child_priv' ctx HDKey {..} i = case hd_key of
  Left _ -> Nothing
  Right _xprv -> pure $!
    let key   = Right (ckd_priv' ctx _xprv i)
        depth = hd_depth + 1
        parent = fingerprint _xprv
        child = ser32 i
    in  HDKey key depth parent child

-- | The same as 'derive_child_pub', but uses a 'Context' to optimise
--   internal calculations.
derive_child_pub' :: Context -> HDKey -> Word32 -> Maybe HDKey
derive_child_pub' ctx HDKey {..} i = do
  (key, parent) <- case hd_key of
    Left _xpub  -> do
      pub <- ckd_pub' ctx _xpub i
      pure $! (pub, fingerprint _xpub)
    Right _xprv ->
      let pub = n' ctx (ckd_priv' ctx _xprv i)
      in  pure $! (pub, fingerprint _xprv)
  let depth = hd_depth + 1
      child = ser32 i
  pure $! HDKey (Left key) depth parent child

-- derivation path expression -------------------------------------------------

-- recursive derivation path
data Path =
    M
  | !Path :| !Word32 -- hardened
  | !Path :/ !Word32
  deriving (Eq, Show)

parse_path :: BS.ByteString -> Maybe Path
parse_path bs = case BS.uncons bs of
    Nothing -> Nothing
    Just (h, t)
      | h == 109  -> go M t -- == 'm'
      | otherwise -> Nothing
  where
    child :: Path -> BS.ByteString -> Maybe (Path, BS.ByteString)
    child pat b = case B8.readInt b of
      Nothing -> Nothing
      Just (fi -> i, etc) -> case BS.uncons etc of
        Nothing -> Just $! (pat :/ i, mempty)
        Just (h, t)
          | h == 39 -> Just $! (pat :| i, t) -- '
          | otherwise -> Just $! (pat :/ i, etc)

    go pat b = case BS.uncons b of
      Nothing -> Just pat
      Just (h, t)
        | h == 47 -> do -- /
            (npat, etc) <- child pat t
            go npat etc
        | otherwise ->
            Nothing

-- | Derive a child node via the provided derivation path.
--
--   Fails with 'Nothing' if derivation is impossible, or if the
--   provided path is invalid.
--
--   >>> let Just hd = master "my very secret master seed"
--   >>> let Just child = derive hd "m/44'/0'/0'/0/0"
--   >>> xpub child
--   "xpub6FvaeGNFmCkLky6jwefrUfyH7gCGSAUckRBANT6wLQkm4eWZApsf4LqAadtbM8EBFfuKGFgzhgta4ByP6xnBodk2EV7BiwxCPLgu13oYWGp"
derive
  :: HDKey
  -> BS.ByteString -- ^ derivation path
  -> Maybe HDKey
derive hd pat = case parse_path pat of
    Nothing -> Nothing
    Just p  -> go p
  where
    go = \case
      M -> pure hd
      p :| i -> do
        hdkey <- go p
        derive_child_priv hdkey (0x8000_0000 + i) -- 2 ^ 31
      p :/ i -> do
        hdkey <- go p
        derive_child_priv hdkey i

-- | Derive a child node via the provided derivation path.
--
--   Fails with 'error' if derivation is impossible, or if the provided
--   path is invalid.
--
--   >>> let other_child = derive_partial hd "m/44'/0'/0'/0/1"
--   >>> xpub other_child
--   "xpub6FvaeGNFmCkLpkT3uahJnGPTfEX62PtH7uZAyjtru8S2FvPuYTQKn8ct6CNQAwHMXaGN6EYuwi1Tz2VD7msftH8VTAtzgNra9CForA9FBP4"
derive_partial
  :: HDKey
  -> BS.ByteString
  -> HDKey
derive_partial hd pat = case derive hd pat of
  Nothing -> error "ppad-bip32 (derive_partial): couldn't derive extended key"
  Just hdkey -> hdkey

-- | The same as 'derive', but uses a 'Context' to optimise internal
--   calculations.
--
--   >>> let !ctx = precompute
--   >>> let Just child = derive' ctx hd "m/44'/0'/0'/0/0"
derive'
  :: Context
  -> HDKey
  -> BS.ByteString -- ^ derivation path
  -> Maybe HDKey
derive' ctx hd pat = case parse_path pat of
    Nothing -> Nothing
    Just p  -> go p
  where
    go = \case
      M -> pure hd
      p :| i -> do
        hdkey <- go p
        derive_child_priv' ctx hdkey (0x8000_0000 + i) -- 2 ^ 31
      p :/ i -> do
        hdkey <- go p
        derive_child_priv' ctx hdkey i

-- | The same as 'derive_partial', but uses a 'Context' to optimise internal
--   calculations.
--
--   >>> let !ctx = precompute
--   >>> let child = derive_partial' ctx hd "m/44'/0'/0'/0/0"
derive_partial'
  :: Context
  -> HDKey
  -> BS.ByteString
  -> HDKey
derive_partial' ctx hd pat = case derive' ctx hd pat of
  Nothing ->
    error "ppad-bip32 (derive_partial'): couldn't derive extended key"
  Just hdkey -> hdkey

-- serialization --------------------------------------------------------------

_MAINNET_PUB, _MAINNET_PRV :: Word32
_TESTNET_PUB, _TESTNET_PRV :: Word32

_MAINNET_PUB_BYTES, _MAINNET_PRV_BYTES :: BS.ByteString
_TESTNET_PUB_BYTES, _TESTNET_PRV_BYTES :: BS.ByteString

_MAINNET_PUB = 0x0488B21E
_MAINNET_PUB_BYTES = "\EOT\136\178\RS"

_MAINNET_PRV = 0x0488ADE4
_MAINNET_PRV_BYTES = "\EOT\136\173\228"

_TESTNET_PUB = 0x043587CF
_TESTNET_PUB_BYTES = "\EOT5\135\207"

_TESTNET_PRV = 0x04358394
_TESTNET_PRV_BYTES = "\EOT5\131\148"

-- | Serialize a mainnet extended public key in base58check format.
--
--   >>> let Just hd = master "my very secret entropy"
--   >>> xpub hd
--   "xpub661MyMwAqRbcGTJPtZRqZyrvjxHCfhqXeiqb5GVU3EGuFBy4QxT3yt8iiHwZTiCzZFyuyNiqXB3eqzqFZ8z4L6HCrPSkDVFNuW59LXYvMjs"
xpub :: HDKey -> BS.ByteString
xpub x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> _serialize _MAINNET_PUB x
    Right e -> _serialize _MAINNET_PUB HDKey {
        hd_key = Left (n e)
      , ..
      }

-- | Serialize a mainnet extended private key in base58check format.
--
--   >>> xprv hd
--   Just "xprv9s21ZrQH143K3yDvnXtqCqvCBvSiGF7gHVuzGt5rUtjvNPdusR8oS5pErywDM1jDDTcLpNNCbg9a9NuidBczRzSUp7seDeu8am64h6nfdrg"
xprv :: HDKey -> Maybe BS.ByteString
xprv x@HDKey {..} = case hd_key of
  Left _  -> Nothing
  Right _ -> do
    let ser = _serialize _MAINNET_PRV x
    pure $! (B58C.encode . BS.toStrict . BSB.toLazyByteString) ser

-- | Serialize a testnet extended public key in base58check format.
--
--   >>> tpub hd
--   "tpubD6NzVbkrYhZ4YFVFLkQvmuCJ55Nrf6LbCMRtRpYcP92nzUdmVBJ98KoYxL2LzDAEMAWpaxEi4GshYBKrwzqJDXjVuzC3u1ucVTfZ6ZD415x"
tpub :: HDKey -> BS.ByteString
tpub x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> _serialize _TESTNET_PUB x
    Right e -> _serialize _TESTNET_PUB HDKey {
      hd_key = Left (n e)
      , ..
      }

-- | Serialize a testnet extended private key in base58check format.
--
--   >>> tprv hd
--   Just "tprv8ZgxMBicQKsPenTTT6kLNVYBW3rvVm9gd3q79JWJxsEQ9zNzrnUYwqBgnA6sMP7Xau97pTyxm2jNcETTkPxwF3i5Lm5wt1dBVrqV8kKi5v5"
tprv :: HDKey -> Maybe BS.ByteString
tprv x@HDKey {..} = case hd_key of
  Left _  -> Nothing
  Right _ -> do
    let ser = _serialize _TESTNET_PRV x
    pure $! (B58C.encode . BS.toStrict . BSB.toLazyByteString) ser

_serialize :: Word32 -> HDKey -> BSB.Builder
_serialize version HDKey {..} =
     BSB.word32BE version
  <> BSB.word8 hd_depth
  <> BSB.byteString hd_parent
  <> BSB.byteString hd_child
  <> case hd_key of
       Left (XPub (X pub cod)) ->
            BSB.byteString cod
         <> BSB.byteString (Secp256k1.serialize_point pub)
       Right (XPrv (X sec cod)) ->
            BSB.byteString cod
         <> BSB.word8 0x00
         <> BSB.byteString (unroll32 sec)

-- parsing --------------------------------------------------------------------

data KeyType =
    Pub
  | Prv

-- | Parse a base58check-encoded 'ByteString' into a 'HDKey'.
--
--   Fails with 'Nothing' if the provided key is invalid.
--
--   >>> let Just hd = master "my very secret entropy"
--   >>> let Just my_xprv = parse (xprv hd)
--   >>> my_xprv == hd
--   True
parse :: BS.ByteString -> Maybe HDKey
parse b58 = do
    bs <- B58C.decode b58
    case BS.splitAt 4 bs of
      (version, etc)
        | version == _MAINNET_PUB_BYTES || version == _TESTNET_PUB_BYTES ->
            parse_pub etc
        | version == _MAINNET_PRV_BYTES || version == _TESTNET_PRV_BYTES ->
            parse_prv etc
        | otherwise ->
            Nothing
  where
    parse_pub = _parse Pub
    parse_prv = _parse Prv

    _parse ktype bs = do
      (hd_depth, etc0) <- BS.uncons bs
      let (hd_parent, etc1) = BS.splitAt 4 etc0
      guard (BS.length hd_parent == 4)
      let (hd_child, etc2) = BS.splitAt 4 etc1
      guard (BS.length hd_child == 4)
      let (cod, etc3) = BS.splitAt 32 etc2
      guard (BS.length cod == 32)
      let (key, etc4) = BS.splitAt 33 etc3
      guard (BS.length key == 33)
      guard (BS.length etc4 == 0)
      hd <- case ktype of
        Pub -> do
          pub <- Secp256k1.parse_point key
          let hd_key = Left (XPub (X pub cod))
          pure HDKey {..}
        Prv -> do
          (b, unsafe_roll32 -> prv) <- BS.uncons key -- safe, guarded keylen
          guard (b == 0)
          let com0 = W.gt prv 0
              com1 = W.lt prv Secp256k1._CURVE_Q
          guard (C.decide (C.and com0 com1))
          let hd_key = Right (XPrv (X prv cod))
          pure HDKey {..}
      guard (valid_lineage hd)
      pure hd
    {-# INLINE _parse #-}

valid_lineage :: HDKey -> Bool
valid_lineage HDKey {..}
  | hd_depth == 0 =
         hd_parent == "\NUL\NUL\NUL\NUL"
      && hd_child == "\NUL\NUL\NUL\NUL"
  | otherwise = True

