{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Data.String.Conversions
import Test.Hspec
import Text.XML.DSig
import Util

import qualified Samples


spec :: Spec
spec = describe "xml:dsig" $ do
  describe "key handling" $ do
    it "parseKeyInfo" $ do
      keyinfo <- readSampleIO "microsoft-idp-keyinfo.xml"
      let want = Samples.microsoft_idp_keyinfo
          Right (SignCreds _ (SignKeyRSA have)) = keyInfoToCreds =<< parseKeyInfo keyinfo
      have `shouldBe` want

  describe "verify" $ do
    it "verify" $ do
      let key = Samples.microsoft_idp_keyinfo
      raw <- cs <$> readSampleIO "microsoft-authnresponse-2.xml"
      verifyIO key raw "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6" `shouldReturn` Right ()
