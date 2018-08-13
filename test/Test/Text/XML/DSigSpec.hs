{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Control.Monad ((>=>))
import Data.Either
import Data.String.Conversions
import Samples (pubA, privA, pubB)
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

  describe "verifyRoot vs. signRoot" $ do
    let check :: HasCallStack => Bool -> Bool -> Either String () -> Spec
        check withMatchingCreds withID expected =
          it (show (withMatchingCreds, withID, expected)) $ do
            (privCreds, pubCreds) <- mkcrds withMatchingCreds
            putStrLn . cs . renderLBS def . either error id $ signRoot privCreds (doc withID)
            (verifyRoot pubCreds . renderLBS def =<< signRoot privCreds (doc withID)) `shouldBe` expected

        mkcrds, _mkcrdsReal, _mkcrdsCached :: Bool -> IO (SignPrivCreds, SignCreds)
        mkcrds = _mkcrdsCached

        _mkcrdsReal = \case
          True  -> mkSignCreds keysize
          False -> (,) <$> (fst <$> mkSignCreds keysize) <*> (snd <$> mkSignCreds keysize)
        keysize = 192  -- not long enough for security, but hopefully long enough for swift testing

        _mkcrdsCached = pure . \case
          True  -> (privA, pubA)
          False -> (privA, pubB)

        someID withID = Map.fromList [("ID", UUID.toText UUID.nil) | withID]
        doc withID = Document (Prologue [] Nothing []) (Element "root" (someID withID) root) []
        root = [xml|
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
      (privCreds, _pubCreds) <- mkcrds True
      let outcome = either (error . show) cs
            $ renderLBS def <$> signRoot privCreds (doc False)
      (outcome `shouldContain`) `mapM_` ["bloo", "ack", "hackach", "hackach"]
