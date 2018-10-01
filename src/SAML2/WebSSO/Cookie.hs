{-# LANGUAGE OverloadedStrings #-}

-- | A high-level wrapper for 'Web.Cookie.SetCookie' that interfaces with servant types, generates
-- and verifies cookie name from the type, handles randomness generation, and cookie deletion.
module SAML2.WebSSO.Cookie
  ( SimpleSetCookie(..)
  , cookieToHeader
  , toggleCookie
  , setSimpleCookieValue
  ) where

import Control.Monad.Except
import Data.Binary.Builder (toLazyByteString)
import Data.Proxy
import Data.String.Conversions
import GHC.TypeLits (KnownSymbol, symbolVal)
import GHC.Types
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Servant.API as Servant hiding (URI(..))
import Web.Cookie

import qualified Data.ByteString.Builder as SBSBuilder
import qualified Data.Text as ST
import qualified Network.HTTP.Types.Header as HttpTypes


newtype SimpleSetCookie name = SimpleSetCookie { fromSimpleSetCookie :: SetCookie }
  deriving (Eq, Show)

instance KnownSymbol name => ToHttpApiData (SimpleSetCookie name) where
  toUrlPiece = cs . SBSBuilder.toLazyByteString . renderSetCookie . fromSimpleSetCookie

instance KnownSymbol name => FromHttpApiData (SimpleSetCookie name) where
  parseUrlPiece = headerValueToCookie

cookieToHeader :: SimpleSetCookie name -> HttpTypes.Header
cookieToHeader =
  ("set-cookie",) . cs . toLazyByteString .
  renderSetCookie . fromSimpleSetCookie

cookieName :: forall (name :: Symbol). KnownSymbol name => Proxy name -> SBS
cookieName Proxy = cs $ symbolVal (Proxy @name)

headerValueToCookie :: forall name. KnownSymbol name => ST -> Either ST (SimpleSetCookie name)
headerValueToCookie txt = do
  let cookie = parseSetCookie $ cs txt
  case ["missing cookie name"  | setCookieName cookie == ""] <>
       ["wrong cookie name"    | setCookieName cookie /= cookieName (Proxy @name)] <>
       ["missing cookie value" | setCookieValue cookie == ""]
    of errs@(_:_) -> throwError $ ST.intercalate ", " errs
       []         -> pure (SimpleSetCookie cookie)

toggleCookie :: forall name. KnownSymbol name => SBS -> Maybe ST -> SimpleSetCookie name
toggleCookie path = SimpleSetCookie . \case
  Just value -> cookie
    { setCookieValue = cs value
    }
  Nothing -> cookie
    { setCookieValue = ""
    , setCookieExpires = Just $ fromTime beginningOfTime
    , setCookieMaxAge = Just (-1)
    }
  where
    cookie = defaultSetCookie
      { setCookieName = cookieName (Proxy @name)
      , setCookieSecure = True
      , setCookiePath = Just path
      }

beginningOfTime :: Time
beginningOfTime = unsafeReadTime "1970-01-01T00:00:00Z"

setSimpleCookieValue :: SimpleSetCookie name -> SBS
setSimpleCookieValue = setCookieValue . fromSimpleSetCookie
