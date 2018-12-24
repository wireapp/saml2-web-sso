{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module SAML2.WebSSO.Error where

import Data.String.Conversions
import Data.Void (Void, absurd)
import Servant.Server


data Error err
  = UnknownIdP LT
  | Forbidden LT
  | BadSamlResponseBase64Error LT
  | BadSamlResponseXmlError LT
  | BadSamlResponseSamlError LT
  | BadSamlResponseFormFieldMissing
  | BadSamlResponseIssuerMissing
  | BadSamlResponseNoAssertions
  | BadSamlResponseAssertionWithoutID
  | BadSamlResponseInvalidSignature LT
  | BadServerConfig LT
  | InvalidCert LT
  | UnknownError
  | CustomServant ServantErr
  | CustomError err
  deriving (Eq, Show)

type SimpleError = Error Void


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
toServantErr (CustomServant err)   = err
toServantErr (CustomError avoid)   = absurd avoid
