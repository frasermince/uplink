{-|

Address datatypes and operations.

-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Address (
  -- ** Types
  Address,
  rawAddr,
  fromRaw,
  emptyAddr,
  isEmpty,
  shortAddr,
  addrSize,

  -- ** Tagging
  AContract,
  AAccount,
  AAsset,
  showAddr,

  -- ** Parsing
  parseAddr,
  parseAddress,

  -- ** Validation
  deriveHash,
  deriveAddress,
  verifyAddress,
  validateAddress,
  recoverAddress,
  recoverAddress',

  putAddress,
  getAddress,

  -- ** Generation
  newAddr,
  newAddrs,
  newPair,
  newTriple,

) where

import Prelude (Show(..), show)
import Protolude hiding (Show, show)
import qualified GHC.TypeLits as Lits

import Encoding
import qualified Key
import qualified Hash
import Script.Pretty (Pretty(..), squotes)

import Control.Monad (fail)

import Data.Aeson (Value(..), ToJSON(..), FromJSON(..), ToJSONKey(..), FromJSONKey(..), FromJSONKeyFunction(..))

import Data.Aeson.Types (typeMismatch, toJSONKeyText)
import Data.Hashable (Hashable)
import Data.Serialize (Serialize, encode, decode)
import qualified Data.Binary as B
import qualified Data.Serialize as S
import qualified Data.ByteString as BS

import Database.PostgreSQL.Simple.FromRow   (FromRow)
import Database.PostgreSQL.Simple.ToRow     (ToRow(..))
import Database.PostgreSQL.Simple.ToField   (ToField(..))
import Database.PostgreSQL.Simple.FromField (FromField(..), ResultError(..), returnError)

import Crypto.Number.Serialize (i2osp)

-------------------------------------------------------------------------------
-- Address
-------------------------------------------------------------------------------

-- | Size of a base58 encoded bytestring address
addrSize :: Int
addrSize = Hash.hashSize

-- | XXX: Roll underlying type to use Digest SHA3_256
-- | XXX: phantom type parameter to distinguish address types

-- | A ledger address, derived from elliptic curve point
newtype Address a = Address ByteString
  deriving (Eq, Ord, Monoid, Generic, NFData, B.Binary, Hashable, Hash.Hashable, Read, Typeable)

instance ToJSON (Address a) where
  toJSON (Address bs) = Data.Aeson.String (decodeUtf8 bs)

instance FromJSON (Address a) where
  parseJSON (String v) =
    case unb58 (encodeUtf8 v) of
      Nothing -> fail "String is not valid base 58 encoded."
      Just bs ->
        case validateAddress (Address (encodeUtf8 v)) of
          False -> fail "String is malformed address."
          True  -> pure (Address (encodeUtf8 v))
  parseJSON _ = fail "Cannot parse address from non-string."

instance FromJSONKey (Address a) where
  fromJSONKey = Address . encodeUtf8 <$> fromJSONKey

instance Serialize (Address a) where
  put (Address bs) = case unb58 bs of
    Just raw -> S.putByteString raw
    Nothing  -> panic ("Cannot serialize invalid address:" <> (toS (show bs)))
  get = Address . b58 <$> S.getByteString addrSize

instance Pretty (Address a) where
  ppr (Address bs) = squotes $ ppr bs


instance ToJSONKey (Address a) where
  toJSONKey = toJSONKeyText (decodeUtf8 . rawAddr)

-- | Type level tags of address type
data AContract
data AAccount
data AAsset

type family AddrTag i where
  AddrTag AContract = "c"
  AddrTag AAccount  = "u"
  AddrTag AAsset    = "a"
  AddrTag _         = Lits.TypeError (Lits.Text "Cannot lower tag of unknown address")

-- | Lower the typelevel tag of an address to it's display value.
{-showAddr :: forall a. (KnownSymbol (AddrTag a)) => (Address a) -> Text-}
showAddr :: forall a b. (KnownSymbol (AddrTag a)) => (a, Address b) -> Text
showAddr (_, addr) = toS (symbolVal (Proxy :: Proxy (AddrTag a))) <> toS (show addr)

putAddress :: forall a. Address.Address a -> S.PutM ()
putAddress addr =
  case unb58 $ rawAddr addr of
    Nothing -> fail "Invalid base58 encoded address."
    Just addr' -> S.putByteString addr'

getAddress :: forall a. S.Get (Address.Address a)
getAddress =  parseAddress . b58 <$> S.getByteString addrSize

-- | Extract underlying bytes from an 'Address'
rawAddr :: forall a. Address a -> ByteString
rawAddr (Address n) = n

-- | Build an 'Address' from a bytestring. ( Not safe )
fromRaw :: forall a. ByteString -> Address a
fromRaw bs =
  let addr = Address bs
  in if validateAddress addr
    then addr
    else panic $ "Cannot validate address as input to \'fromRaw\': " <> toS bs

-- | Empty address
emptyAddr :: forall a. Address a
emptyAddr = Address (b58 (BS.replicate addrSize 0))

-- | Check if address is empty
isEmpty :: forall a. Address a -> Bool
isEmpty (Address s) = s == mempty

-- | Shortened address for logging
shortAddr :: forall a. Address a -> ByteString
shortAddr (Address addr) = BS.take 7 addr

-- | Derive an address from a public key
--
-- > address(x,y) = addrHash(string(x) <> string(y))
deriveAddress :: forall a. Key.PubKey -> Address a
deriveAddress pub = Address (b58 addr)
  where
    (x, y) = Key.extractPoint pub
    addr   = deriveHash pstr
    pstr   = toS (show x) <> toS (show y)

-- | Address derivation function, maps a hash of a EC point to a unique,
-- irreversible identity that uniquely defines a participant in the network and
-- any participant can verify integrity of it's coherence to a public key.
--
-- > addrHash(n) = sha256(sha256(ripemd160(sha256(n))))
deriveHash :: ByteString -> ByteString
deriveHash = Hash.sha256Raw . Hash.sha256Raw . Hash.ripemd160Raw . Hash.sha256Raw

-- | Validate whether an address is a well-formed B58 encoded hash.
validateAddress :: forall a. Address a -> Bool
validateAddress (Address s) = case unb58 s of
  Nothing  -> False
  Just sha -> Hash.validateSha sha

-- | Parses a ByteStrig into an Address. Panics on invalid inputs.
parseAddress :: forall a. ByteString -> Address a
parseAddress = fromRaw

-- | XXXX why do we have two of these
parseAddr :: forall a. ByteString -> Maybe (Address a)
parseAddr bs =
  let addr = Address bs
  in if validateAddress addr
    then Just addr
    else Nothing

-- | Verify an address is derived from a given public key.
verifyAddress :: forall a. Key.PubKey -> Address a -> Bool
verifyAddress pub a@(Address s) = case unb58 s of
  Nothing -> False
  Just _  -> deriveAddress pub == a

recoverAddress :: forall a. ByteString -> ByteString -> Either Key.InvalidSignature (Address a, Address a)
recoverAddress sig msg = flip recoverAddress' msg <$> Key.decodeSig sig

recoverAddress' :: forall a. Key.Signature -> ByteString -> (Address a, Address a)
recoverAddress' sig = bimap deriveAddress deriveAddress . Key.recover sig

-- Hackish show method for debugging
instance Show (Address a) where
  show (Address "") = "<empty>"
  show (Address x) = toS x

  showsPrec _ (Address "") = (++) "<empty>"
  showsPrec _ (Address x) = (++) (toS x)

-------------------------------------------------------------------------------
-- Generation
-------------------------------------------------------------------------------

-- | Generate a new random 'Address' from random key.
newAddr :: forall a. IO (Address a)
newAddr = Key.new >>= \(pub, priv) -> pure (deriveAddress pub)

-- | Generate a key public key, address pair.
newPair :: forall a. IO (Key.PubKey, Address a)
newPair = Key.new >>= \(pub, priv) -> pure (pub, deriveAddress pub)

-- | Generate a key private key, public key, address pair.
newTriple :: forall a. IO (Key.PrivateKey, Key.PubKey, Address a)
newTriple = Key.new >>= \(pub, priv) -> pure (priv, pub, deriveAddress pub)

-- | Generate a set of new addresses
newAddrs :: forall a. Int -> IO [Address a]
newAddrs n = replicateM n newAddr

-------------------------------------------------------------------------------
-- Postgres DB
-------------------------------------------------------------------------------

-- XXX Maybe this is wrong (trying to convert it to `Text` before toField).
instance ToField (Address a) where
  toField = toField . decodeUtf8 . rawAddr

instance Typeable a => FromField (Address a) where
  fromField f mdata =
    case mdata of
      Nothing   -> returnError UnexpectedNull f ""
      Just addr
        | validateAddress (fromRaw addr) -> return $ fromRaw addr
        | otherwise -> returnError ConversionFailed f "Invalid Address read from DB"

instance ToRow (Address a)
instance FromRow (Address a)
