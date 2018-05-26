module Main where

import Data.String
import Lens.Micro ((^.), (&))
import Network.Wai.Handler.Warp (runSettings, defaultSettings, setHost, setPort)
import SAML2.WebSSO.API.Example (app)
import SAML2.WebSSO.Config


main :: IO ()
main = do
  config <- configIO
  let settings = defaultSettings
        & setHost (fromString $ config ^. cfgSPHost)
        . setPort (config ^. cfgSPPort)
  runSettings settings =<< app
