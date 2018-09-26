{-# LANGUAGE OverloadedStrings #-}

module Test.SAML2.WebSSO.TypesSpec (spec) where

import SAML2.WebSSO
import Test.Hspec
import Util

spec :: Spec
spec = do
  describe "rspInResponseTo" $ do
    it "works" $ do
      Right (aresp :: AuthnResponse) <- decode <$> readSampleIO "microsoft-authnresponse-2.xml"
      rspInResponseTo aresp `shouldBe` Right (ID {renderID = "idcf2299ac551b42f1aa9b88804ed308c2"})

  describe "roundtrip" $ do
    it "works" $ do
      pendingWith "TODO: find all types that we have hand-written json instances for."
