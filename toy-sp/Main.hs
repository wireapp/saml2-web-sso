module Main where

import Data.String
import Lens.Micro ((^.), (&))
import Network.Wai.Handler.Warp (runSettings, defaultSettings, setHost, setPort)
import SAML.WebSSO.API.Example (app)
import SAML.WebSSO.Config


main :: IO ()
main = do
  config <- getConfig
  let settings = defaultSettings
        & setHost (fromString $ config ^. cfgSPHost)
        . setPort (config ^. cfgSPPort)
  runSettings settings app
