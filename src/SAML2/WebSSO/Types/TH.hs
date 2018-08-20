module SAML2.WebSSO.Types.TH (deriveJSONOptions) where

import Data.Aeson
import Data.Char
import Lens.Micro

deriveJSONOptions :: Options
deriveJSONOptions = defaultOptions { fieldLabelModifier = labelmod }

labelmod :: String -> String
labelmod = (ix 0 %~ toLower) . dropWhile (not . isUpper)
