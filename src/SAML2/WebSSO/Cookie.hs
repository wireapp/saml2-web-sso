{-# LANGUAGE OverloadedStrings #-}

-- | A wrapper for 'Web.Cookie.SetCookie' that lets us avoid orphan
-- instances.
module SAML2.WebSSO.Cookie
  ( SetSAMLCookie
  , setSAMLCookieValue
  , cookieToHeader
  , headerValueToCookie
  , togglecookie
  ) where

import Control.Monad.Except
import Data.Binary.Builder (toLazyByteString)
import Data.String.Conversions
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Servant.API as Servant hiding (URI(..))
import Web.Cookie

import qualified Data.ByteString.Builder as SBSBuilder
import qualified Data.Text as ST
import qualified Network.HTTP.Types.Header as HttpTypes


newtype SetSAMLCookie = SetSAMLCookie { fromSAMLCookie :: SetCookie }
  deriving (Eq, Show)

instance ToHttpApiData SetSAMLCookie where
  toUrlPiece = cs . SBSBuilder.toLazyByteString . renderSetCookie . fromSAMLCookie

instance FromHttpApiData SetSAMLCookie where
  parseUrlPiece = headerValueToCookie

cookieToHeader :: SetSAMLCookie -> HttpTypes.Header
cookieToHeader =
  ("set-cookie",) . cs . toLazyByteString .
  renderSetCookie . fromSAMLCookie

headerValueToCookie :: ST -> Either ST SetSAMLCookie
headerValueToCookie txt = do
  let cookie = parseSetCookie $ cs txt
  case ["missing cookie name"  | setCookieName cookie == ""] <>
       ["wrong cookie name"    | setCookieName cookie /= cookiename] <>
       ["missing cookie value" | setCookieValue cookie == ""]
    of errs@(_:_) -> throwError $ ST.intercalate ", " errs
       []         -> pure (SetSAMLCookie cookie)

cookiename :: SBS
cookiename = "saml2-web-sso_sp_credentials"

togglecookie :: Maybe ST -> SetSAMLCookie
togglecookie = SetSAMLCookie . \case
  Just nick -> cookie
    { setCookieValue = cs nick
    }
  Nothing -> cookie
    { setCookieValue = ""
    , setCookieExpires = Just . fromTime $ unsafeReadTime "1970-01-01T00:00:00Z"
    , setCookieMaxAge = Just (-1)
    }
  where
    cookie = defaultSetCookie
      { setCookieName = cookiename
      , setCookieSecure = True
      , setCookiePath = Just "/"
      }

setSAMLCookieValue :: SetSAMLCookie -> SBS
setSAMLCookieValue = setCookieValue . fromSAMLCookie
