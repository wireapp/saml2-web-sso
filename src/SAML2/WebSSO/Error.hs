{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module SAML2.WebSSO.Error where

import Data.String.Conversions
import Data.Void (Void, absurd)
import Servant.Server


data Error err
  = UnknownIdP LT
  | Forbidden LT
  | BadSamlResponse LT
  | BadServerConfig LT
  | UnknownError
  | CustomServant ServantErr
  | CustomError err
  deriving (Eq, Show)

type SimpleError = Error Void


toServantErr :: SimpleError -> ServantErr
toServantErr (UnknownIdP msg)      = err404 { errBody = cs $ "Unknown IdP: " <> msg }
toServantErr (Forbidden msg)       = err403 { errBody = cs $ msg }
toServantErr (BadSamlResponse msg) = err400 { errBody = cs $ msg }
toServantErr (BadServerConfig msg) = err400 { errBody = cs $ "Invalid server config: " <> msg }
toServantErr UnknownError          = err500 { errBody = "Internal server error.  Please consult the logs." }
toServantErr (CustomServant err)   = err
toServantErr (CustomError avoid)   = absurd avoid
