module SAML.WebSSO.Config.TH (deriveJSONOptions) where

import Data.Aeson
import Data.Char

deriveJSONOptions :: Options
deriveJSONOptions = defaultOptions { fieldLabelModifier = labelmod }

labelmod :: String -> String
labelmod = camelTo2 '_' . dropWhile (not . isUpper)
