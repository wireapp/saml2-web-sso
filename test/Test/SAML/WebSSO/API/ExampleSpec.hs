{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML.WebSSO.API.ExampleSpec (spec) where

import Data.Typeable
import SAML.WebSSO.API.Example (app')
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import TestSP

spec :: Spec
spec = describe "API.Example" $ do
  describe "meta" . with (pure (app' (Proxy :: Proxy TestSP) testCtx1)) $ do
    it "responds with 200" $ do
      get "/sso/meta" `shouldRespondWith` 200
      get "/sp/logout/local" `shouldRespondWith` 302
