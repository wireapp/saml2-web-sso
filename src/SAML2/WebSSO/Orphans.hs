{-# OPTIONS_GHC -fno-warn-orphans #-}  -- FUTUREWORK: disallow orphans.

module SAML2.WebSSO.Orphans where

import Data.Aeson
import Data.String.Conversions
import Data.X509 as X509
import Text.XML.DSig
import Text.XML.Util (parseURI', renderURI)
import URI.ByteString


instance FromJSON URI where
  parseJSON = (>>= either unerror pure . parseURI') . parseJSON
    where unerror = fail . ("could not parse config: " <>) . show

instance ToJSON URI where
  toJSON = toJSON . renderURI

instance FromJSON X509.SignedCertificate where
  parseJSON = withText "KeyInfo element" $ either fail pure . parseKeyInfo . cs

instance ToJSON X509.SignedCertificate where
  toJSON = String . cs . renderKeyInfo
