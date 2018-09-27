{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML2.WebSSO.API.ExampleSpec (spec) where

import Data.Typeable
import SAML2.WebSSO.API.Example (app')
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Util

spec :: Spec
spec = describe "API.Example" $ do
  describe "meta" . with (app' (Proxy :: Proxy TestSP) =<< mkTestCtxSimple) $ do
    it "responds with 200" $ do
      get "/sso/meta/b10d2c04-c17e-11e8-bc44-8f4b32e86cdd" `shouldRespondWith` 200
      get "/sp/logout/local" `shouldRespondWith` 307
