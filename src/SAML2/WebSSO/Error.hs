{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module SAML2.WebSSO.Error where

import Data.String.Conversions
import Data.Void (Void, absurd)
import Servant.Server


-- | Set the first phantom type to 'False' to disable the 'CustomVerdict' constructor.
data Error (withRaw :: Bool) err where
  UnknownIdP :: LT -> Error withRaw err
  Forbidden :: LT -> Error withRaw err
  BadSamlResponseBase64Error :: LT -> Error withRaw err
  BadSamlResponseXmlError :: LT -> Error withRaw err
  BadSamlResponseSamlError :: LT -> Error withRaw err
  BadSamlResponseFormFieldMissing :: Error withRaw err
  BadSamlResponseIssuerMissing :: Error withRaw err
  BadSamlResponseNoAssertions :: Error withRaw err
  BadSamlResponseAssertionWithoutID :: Error withRaw err
  BadSamlResponseInvalidSignature :: LT -> Error withRaw err
  BadServerConfig :: LT -> Error withRaw err
  InvalidCert :: LT -> Error withRaw err
  UnknownError :: Error withRaw err
  CustomVerdict ::  RawResponseVerdict -> Error 'True err
  CustomError :: err -> Error withRaw err

deriving instance Eq err => Eq (Error withServantErr err)
deriving instance Show err => Show (Error withServantErr err)

-- | We wrap 'ServantErr' to make it clear this is not merely for error cases, but more often
-- for redirects after successful authentication.
newtype RawResponseVerdict = RawResponseVerdict ServantErr
  deriving (Eq, Show)

type SimpleError = Error 'True Void

toServantErr :: SimpleError -> ServantErr
toServantErr (UnknownIdP msg)      = err404 { errBody = "Unknown IdP: " <> cs msg }
toServantErr (Forbidden msg)       = err403 { errBody = cs msg }
  -- (this should probably be 401, not 403, but according to the standard we would also need to add
  -- a WWW-Authenticate header if we do that, and we are not using saml, not basic auth.
  -- https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#4xx_Client_errors)
toServantErr (BadSamlResponseBase64Error msg)      = err400 { errBody = "Bad response: base64 error: " <> cs msg }
toServantErr (BadSamlResponseXmlError msg)         = err400 { errBody = "Bad response: xml parse error: " <> cs msg }
toServantErr (BadSamlResponseSamlError msg)        = err400 { errBody = "Bad response: saml parse error: " <> cs msg }
toServantErr BadSamlResponseFormFieldMissing       = err400 { errBody = "Bad response: SAMLResponse form field missing from HTTP body" }
toServantErr BadSamlResponseIssuerMissing          = err400 { errBody = "Bad response: no Issuer in AuthnResponse" }
toServantErr BadSamlResponseNoAssertions           = err400 { errBody = "Bad response: no assertions in AuthnResponse" }
toServantErr BadSamlResponseAssertionWithoutID     = err400 { errBody = "Bad response: assertion without ID" }
toServantErr (BadSamlResponseInvalidSignature msg) = err400 { errBody = cs msg }
toServantErr (InvalidCert msg)     = err400 { errBody = "Invalid certificate: " <> cs msg }
toServantErr (BadServerConfig msg) = err400 { errBody = "Invalid server config: " <> cs msg }
toServantErr UnknownError          = err500 { errBody = "Internal server error.  Please consult the logs." }
toServantErr (CustomVerdict (RawResponseVerdict err)) = err
toServantErr (CustomError avoid)   = absurd avoid
