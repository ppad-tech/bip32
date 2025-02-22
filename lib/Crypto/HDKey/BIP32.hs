{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.HDKey.BIP32 (
  -- * Hierarchical deterministic keys
    HDKey(..)
  , master

  -- * Child key derivation functions
  , derive_child_pub
  , derive_child_priv

  -- * Derivation path
  , derive
  , derive_partial

  -- * Serialization
  , xpub
  , xprv
  , tpub
  , tprv

  -- * Parsing
  , parse
  ) where

import Control.Monad (guard)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Data.Bits ((.<<.), (.>>.), (.|.), (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base58Check as B58C
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import Data.Word (Word8, Word32)

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- big-endian bytestring encoding
unroll :: Integer -> BS.ByteString
unroll i = case i of
    0 -> BS.singleton 0
    _ -> BS.reverse $ BS.unfoldr coalg i
  where
    coalg 0 = Nothing
    coalg m = Just (fi m, m .>>. 8)

-- parse 32 bytes to a 256-bit integer
parse256 :: BS.ByteString -> Integer
parse256 bs@(BI.PS _ _ l)
    | l == 32   = BS.foldl' alg 0 bs
    | otherwise = error "ppad-bip32 (parse256): invalid_lineage input"
  where
    alg !a (fi -> !b) = (a .<<. 8) .|. b

-- serialize a 256-bit integer to 32 bytes, left-padding with zeros if
-- necessary. the size of the integer is not checked.
ser256 :: Integer -> BS.ByteString
ser256 (unroll -> u@(BI.PS _ _ l))
  | l < 32 = BS.replicate (32 - l) 0 <> u
  | otherwise = u

-- serialize a 32-bit word, MSB first
ser32 :: Word32 -> BS.ByteString
ser32 w =
  let !mask = 0b00000000_00000000_00000000_11111111
      !w0 = fi (w .>>. 24) .&. mask
      !w1 = fi (w .>>. 16) .&. mask
      !w2 = fi (w .>>. 08) .&. mask
      !w3 = fi w .&. mask
  in  BS.cons w0 (BS.cons w1 (BS.cons w2 (BS.singleton w3))) -- XX

-- extended keys --------------------------------------------------------------

data X a = X !a !BS.ByteString
  deriving (Eq, Show)

newtype XPub = XPub (X Secp256k1.Projective)
  deriving (Eq, Show)

newtype XPrv = XPrv (X Integer)
  deriving (Eq, Show)

class Extended k where
  identifier  :: k -> BS.ByteString

  fingerprint :: k -> BS.ByteString
  fingerprint = BS.take 4 . identifier

instance Extended XPub where
  identifier (XPub (X pub _)) =
    let ser = Secp256k1.serialize_point pub
    in  RIPEMD160.hash (SHA256.hash ser)

instance Extended XPrv where
  identifier (XPrv (X sec _)) =
    let p = Secp256k1.mul Secp256k1._CURVE_G sec
        ser = Secp256k1.serialize_point p
    in  RIPEMD160.hash (SHA256.hash ser)

-- key derivation functions ---------------------------------------------------

hardened :: Word32 -> Bool
hardened = (>= 0x8000_0000)

_master :: BS.ByteString -> Maybe XPrv
_master seed@(BI.PS _ _ l)
  | l < 16 = Nothing
  | l > 64 = Nothing
  | otherwise = do
      let i = SHA512.hmac "Bitcoin seed" seed
          (il, c) = BS.splitAt 32 i
          s = parse256 il
      pure $! (XPrv (X s c))

-- private parent key -> private child key
ckd_priv :: XPrv -> Word32 -> XPrv
ckd_priv _xprv@(XPrv (X sec cod)) i =
    let l = SHA512.hmac cod dat
        (il, ci) = BS.splitAt 32 l
        pil = parse256 il
        ki  = Secp256k1.modQ (pil + sec)
    in  if   pil >= Secp256k1._CURVE_Q || ki == 0 -- negl
        then ckd_priv _xprv (succ i)
        else XPrv (X ki ci)
  where
    dat | hardened i = BS.singleton 0x00 <> ser256 sec <> ser32 i
        | otherwise  =
            let p = Secp256k1.mul Secp256k1._CURVE_G sec
            in  Secp256k1.serialize_point p <> ser32 i

-- public parent key -> public child key
ckd_pub :: XPub -> Word32 -> Maybe XPub
ckd_pub _xpub@(XPub (X pub cod)) i
  | hardened i = Nothing
  | otherwise = do
      let dat = Secp256k1.serialize_point pub <> ser32 i
          l   = SHA512.hmac cod dat
          (il, ci) = BS.splitAt 32 l
          pil = parse256 il
          ki = Secp256k1.mul_unsafe Secp256k1._CURVE_G pil `Secp256k1.add` pub
      if   pil >= Secp256k1._CURVE_Q || ki == Secp256k1._CURVE_ZERO -- negl
      then ckd_pub _xpub (succ i)
      else pure (XPub (X ki ci))

-- private parent key -> public child key
n :: XPrv -> XPub
n (XPrv (X sec cod)) =
  let p = Secp256k1.mul Secp256k1._CURVE_G sec
  in  XPub (X p cod)

-- hierarchical deterministic keys --------------------------------------------

data HDKey = HDKey {
    hd_key    :: !(Either XPub XPrv)
  , hd_depth  :: !Word8
  , hd_parent :: !BS.ByteString
  , hd_child  :: !BS.ByteString
  }
  deriving (Eq, Show)

instance Extended HDKey where
  identifier (HDKey ekey _ _ _) = case ekey of
    Left l -> identifier l
    Right r -> identifier r

master :: BS.ByteString -> Maybe HDKey
master seed = do
  m <- _master seed
  pure $! HDKey {
      hd_key = Right m
    , hd_depth = 0
    , hd_parent = "\NUL\NUL\NUL\NUL" -- 0x0000_0000
    , hd_child = ser32 0
    }

derive_child_priv :: HDKey -> Word32 -> Maybe HDKey
derive_child_priv HDKey {..} i = case hd_key of
  Left _ -> Nothing
  Right _xprv -> pure $!
    let key   = Right (ckd_priv _xprv i)
        depth = hd_depth + 1
        parent = fingerprint _xprv
        child = ser32 i
    in  HDKey key depth parent child

derive_child_pub :: HDKey -> Word32 -> Maybe HDKey
derive_child_pub HDKey {..} i = do
  (key, parent) <- case hd_key of
    Left _xpub  -> do
      pub <- ckd_pub _xpub i
      pure (pub, fingerprint _xpub)
    Right _xprv ->
      let pub = n (ckd_priv _xprv i)
      in  pure (pub, fingerprint _xprv)
  let depth = hd_depth + 1
      child = ser32 i
  pure $ HDKey (Left key) depth parent child

-- derivation path expression -------------------------------------------------

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

derive :: HDKey -> BS.ByteString -> Maybe HDKey
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

derive_partial :: HDKey -> BS.ByteString -> HDKey
derive_partial hd pat = case derive hd pat of
  Nothing -> error "ppad-bip32 (derive_partial): couldn't derive extended key"
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

xpub :: HDKey -> BS.ByteString
xpub x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> _serialize _MAINNET_PUB x
    Right e -> _serialize _MAINNET_PUB HDKey {
        hd_key = Left (n e)
      , ..
      }

xprv :: HDKey -> BS.ByteString
xprv x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> error "ppad-bip32 (xprv): no private key"
    Right _ -> _serialize _MAINNET_PRV x

tpub :: HDKey -> BS.ByteString
tpub x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> _serialize _TESTNET_PUB x
    Right e -> _serialize _TESTNET_PUB HDKey {
      hd_key = Left (n e)
      , ..
      }

tprv :: HDKey -> BS.ByteString
tprv x@HDKey {..} = B58C.encode . BS.toStrict . BSB.toLazyByteString $
  case hd_key of
    Left _  -> error "ppad-bip32 (tprv): no private key"
    Right _ -> _serialize _TESTNET_PRV x

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
         <> BSB.byteString (ser256 sec)

-- parsing --------------------------------------------------------------------

data KeyType =
    Pub
  | Prv

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
          (b, parse256 -> prv) <- BS.uncons key
          guard (b == 0)
          guard (prv > 0 && prv < Secp256k1._CURVE_Q)
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

