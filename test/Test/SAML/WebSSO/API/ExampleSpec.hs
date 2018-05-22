
{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML.WebSSO.API.ExampleSpec (spec) where

import SAML.WebSSO.API.Example (app)
import Test.Hspec hiding (pending)
import Test.Hspec.Wai

spec :: Spec
spec = describe "API.Example" $ do
  describe "meta" . with (pure app) $ do
    it "responds with 200" $ do
      get "/sso/meta" `shouldRespondWith` 200
      get "/sp/logout/local" `shouldRespondWith` 302
