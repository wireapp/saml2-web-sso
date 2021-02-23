{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module SAML2.WebSSO.Types.Email (Email, render, validate) where

import Data.Aeson
import Data.ByteString.Internal
import Data.String.Conversions
import qualified Text.Email.Validate as Email

newtype Email = Email {fromEmail :: Email.EmailAddress}
  deriving (Eq, Ord, Show)

render :: ConvertibleStrings ByteString s => Email -> s
render = cs . Email.toByteString . fromEmail

validate :: forall s. ConvertibleStrings s ByteString => s -> Either String Email
validate = fmap Email . Email.validate . cs

instance FromJSON Email where
  parseJSON = withText "email address" $ either fail pure . validate

instance ToJSON Email where
  toJSON = String . render
