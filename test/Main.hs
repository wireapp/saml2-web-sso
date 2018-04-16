{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | FUTUREWORK: switch more of the test suite to hspec?  it is now just wrapped around tasty for
-- <https://github.com/hspec/sensei sensei> support.
module Main (main) where

import System.Exit
import Test.Hspec
import Test.Tasty

import qualified Test.SAML.WebSSO.API
import qualified Test.SAML.WebSSO.SP
import qualified Test.SAML.WebSSO.XML.Examples
import qualified Test.SAML.WebSSO.XML.Roundtrip
import qualified Test.Text.XML.DSig

main :: IO ()
main = hspec spec

spec :: Spec
spec = it "Tests" $ mainTasty `shouldThrow` (\case ExitSuccess -> True; _ -> False)

mainTasty :: IO ()
mainTasty = defaultMain $ testGroup "Tests"
  [ Test.SAML.WebSSO.API.tests
  , Test.SAML.WebSSO.SP.tests
  , Test.SAML.WebSSO.XML.Examples.tests
  , Test.SAML.WebSSO.XML.Roundtrip.tests
  , Test.Text.XML.DSig.tests
  ]
