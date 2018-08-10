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

import qualified Crypto.Random as Crypto
import qualified Data.ByteArray as ByteArray
import qualified Data.Map as Map
import qualified Data.UUID as UUID
import qualified Samples


-- do not export this, use only for the tests in this module!
instance Crypto.MonadRandom (Either String) where
  getRandomBytes = pure . ByteArray.pack . (`replicate` 0)


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

  xdescribe "verifyRoot vs. signRoot" $ do
    let check :: HasCallStack => Bool -> Bool -> Either String () -> Spec
        check withMatchingCreds withID expected =
          it (show (withMatchingCreds, withID, expected)) $ do
            (privCreds, pubCreds) <- mkcrds
            (verifyRoot pubCreds . renderLBS def =<< signRoot privCreds doc) `shouldBe` expected
          where
            mkcrds = if withMatchingCreds
              then mkSignCreds 768
              else (,) <$> (fst <$> mkSignCreds 768) <*> (snd <$> mkSignCreds 768)

            someID = Map.fromList [("ID", UUID.toText UUID.nil) | withID]
            doc    = Document (Prologue [] Nothing []) (Element "root" someID root) []
            root   = [xml|
                        <bloo hign="___">
                          <ack hoghn="true">
                            <nonack>
                          hackach
                      |]

    check True True (Right ())
    check True False (Right ())
    check False True (Left "")
    check False False (Left "")

    it "keeps data intact" $ do
      pending  -- TODO: search for 'ack' elem and 'hackach' text.
