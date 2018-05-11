{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}

module Main where

import Lens.Micro ((^.))
import Data.String
import Lens.Micro ((&))
import Network.Wai.Handler.Warp (runSettings, defaultSettings, setHost, setPort)

import SAML.WebSSO.API.Example (app)
import SAML.WebSSO.Config

main :: IO ()
main = do
  let settings = defaultSettings
        & setHost (fromString $ config ^. cfgSPHost)
        . setPort (config ^. cfgSPPort)
  runSettings settings app
