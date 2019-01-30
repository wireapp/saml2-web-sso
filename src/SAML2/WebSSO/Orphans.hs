{-# OPTIONS_GHC -fno-warn-orphans #-}  -- FUTUREWORK: disallow orphans.

module SAML2.WebSSO.Orphans where

import Control.Monad ((<=<))
import Data.Aeson
import Data.String.Conversions
import Data.X509 as X509
import SAML2.Util (parseURI', renderURI, normURI)
import Servant hiding (URI)
import Text.XML.DSig
import URI.ByteString


instance FromJSON URI where
  parseJSON = (>>= either unerror (pure . normURI) . parseURI') . parseJSON
    where unerror = fail . ("could not parse config: " <>) . show

instance ToJSON URI where
  toJSON = toJSON . renderURI

instance ToHttpApiData URI where
  toUrlPiece = renderURI

instance FromHttpApiData URI where
  parseUrlPiece = either (fail . show) pure . parseURI' <=< parseUrlPiece

instance FromJSON X509.SignedCertificate where
  parseJSON = withText "KeyInfo element" $ either fail pure . parseKeyInfo False . cs

instance ToJSON X509.SignedCertificate where
  toJSON = String . cs . renderKeyInfo
