{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Util.Orphans where

import Data.String
import Data.String.Conversions
import Data.UUID as UUID
import SAML2.WebSSO

instance IsString IdPId where
    fromString piece = maybe (error $ "no valid UUID" <> piece) (IdPId) . UUID.fromString $ piece
