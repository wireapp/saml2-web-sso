{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | Case insensitive email type.  This helps mitigate issues with users that get casing wrong
-- in their email addresses.
--
-- (The legal situation is simple: [the local part is case
-- sensitive](https://tools.ietf.org/html/rfc5321), [the domain part is case
-- insensitive](https://tools.ietf.org/html/rfc1035).  However, in practice, the entire email,
-- both local and domain part, are treated as case insensitive almost everywhere.  So for
-- interoperability we need to do the same.)
module SAML2.WebSSO.Types.Email (Email, render, validate) where

import Data.Aeson
import Data.ByteString.Internal
import Data.CaseInsensitive (foldCase)
import Data.String.Conversions
import qualified Text.Email.Validate as Email

newtype Email = Email {fromEmail :: Email.EmailAddress}
  deriving (Eq, Ord, Show)

render :: ConvertibleStrings ByteString s => Email -> s
render = cs . Email.toByteString . fromEmail

validate :: forall s. ConvertibleStrings s ByteString => s -> Either String Email
validate = fmap Email . Email.validate . foldCase . cs

instance FromJSON Email where
  parseJSON = withText "email address" $ either fail pure . validate

instance ToJSON Email where
  toJSON = String . render
