{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Control.Monad ((>=>))
import Data.Either
import Data.String.Conversions
import Test.Hspec
import Text.Hamlet.XML (xml)
import Text.XML
import Text.XML.DSig
import Util

import qualified Data.Map as Map
import qualified Samples


spec :: Spec
spec = describe "xml:dsig" $ do
  describe "parseKeyInfo" $ do
    it "works(1)" $ do
      keyinfo <- readSampleIO "microsoft-idp-keyinfo.xml"
      let want = Samples.microsoft_idp_keyinfo
          Right (SignCreds _ (SignKeyRSA have)) = keyInfoToCreds =<< parseKeyInfo keyinfo
      have `shouldBe` want

    it "works(2)" $ do
      keyinfo <- readSampleIO "okta-keyinfo-1.xml"
      (keyInfoToCreds =<< parseKeyInfo keyinfo) `shouldSatisfy` isRight

  describe "verify" $ do
    it "works" $ do
      Right keyinfo <- (parseKeyInfo >=> keyInfoToCreds) <$> readSampleIO "microsoft-idp-keyinfo.xml"
      raw <- cs <$> readSampleIO "microsoft-authnresponse-2.xml"
      verify keyinfo raw "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6" `shouldBe` Right ()

  describe "verifyRoot" $ do
    it "works" $ do
      Right keyinfo <- (parseKeyInfo >=> keyInfoToCreds) <$> readSampleIO "microsoft-idp-keyinfo.xml"
      raw <- cs <$> readSampleIO "microsoft-meta-2.xml"
      verifyRoot keyinfo raw `shouldBe` Right ()

  describe "verifyRoot vs. signRoot" $ do
    let check :: HasCallStack => SignPrivCreds -> SignCreds -> Bool -> Expectation
        check privCreds pubCreds withID =
          (verifyRoot pubCreds . renderLBS def . signRoot privCreds $ doc) `shouldBe` Right ()
          where
            someID = Map.fromList [("ID", "fde150a6-9bc6-11e8-a30b-dbd406c1d75d") | withID]
            doc    = Document (Prologue [] Nothing []) (Element "root" someID root) []
            root   = [xml|
                        <bloo hign="___">
                          <ack hoghn="true">
                            <nonack>
                          hackach
                      |]

    it "pass on matching keys" $ do
      (privCreds, pubCreds) <- mkSignCreds 768
      check privCreds pubCreds `mapM_` [minBound..]

    it "reject on key mismatch" $ do
      (privCreds, _) <- mkSignCreds 768
      (_, pubCreds)  <- mkSignCreds 768
      check privCreds pubCreds `mapM_` [minBound..]
