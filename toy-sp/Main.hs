{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}

module Main where

import Data.Monoid ((<>))
import Lens.Micro ((&))
import Network.Wai.Handler.Warp (runSettings, defaultSettings, setHost, setPort, getHost, getPort)
import SAML.WebSSO.API (app)

main :: IO ()
main = do
  let settings = defaultSettings & setPort 8081 . setHost "localhost"
  putStrLn $ "starting web server on " <> show (getHost settings) <> ":" <> show (getPort settings)
  runSettings settings app
