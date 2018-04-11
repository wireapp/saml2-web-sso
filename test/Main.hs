{-# LANGUAGE ScopedTypeVariables #-}

-- | TODO: auto-generate this module using tasty-discover.
module Main (main) where

import Test.Tasty

import qualified Test.SAML.WebSSO.API

main :: IO ()
main = defaultMain $ testGroup "Tests"
  [ Test.SAML.WebSSO.API.tests
  ]
