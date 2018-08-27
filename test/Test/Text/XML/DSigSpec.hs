{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Control.Monad ((>=>))
import Data.Either
import Data.String.Conversions
import SAML2.WebSSO.Test.Credentials
import Test.Hspec
import Text.Hamlet.XML (xml)
import Text.XML
import Text.XML.DSig
import Util

import qualified Data.Map as Map
import qualified Data.UUID as UUID
import qualified Samples


spec :: Spec
spec = describe "xml:dsig" $ do
  describe "parseKeyInfo" $ do
    it "works(1)" $ do
      keyinfo <- readSampleIO "microsoft-idp-keyinfo.xml"
      let want = Samples.microsoft_idp_keyinfo
          Right (SignCreds _ (SignKeyRSA have)) = certToCreds =<< parseKeyInfo keyinfo
      have `shouldBe` want

    it "works(2)" $ do
      keyinfo <- readSampleIO "okta-keyinfo-1.xml"
      (certToCreds =<< parseKeyInfo keyinfo) `shouldSatisfy` isRight

    it "works against mkSignCredsWithCert" $ do
      (_privcreds, creds, cert) <- mkSignCredsWithCert Nothing 192
      verifySelfSignature cert `shouldBe` Right ()
      certToCreds cert `shouldBe` Right creds

  describe "verify" $ do
    it "works" $ do
      Right keyinfo <- (parseKeyInfo >=> certToCreds) <$> readSampleIO "microsoft-idp-keyinfo.xml"
      raw <- cs <$> readSampleIO "microsoft-authnresponse-2.xml"
      verify keyinfo raw "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6" `shouldBe` Right ()

  describe "verifyRoot" $ do
    it "works" $ do
      Right keyinfo <- (parseKeyInfo >=> certToCreds) <$> readSampleIO "microsoft-idp-keyinfo.xml"
      raw <- cs <$> readSampleIO "microsoft-meta-2.xml"
      verifyRoot keyinfo raw `shouldBe` Right ()

  describe "verifyRoot vs. signRoot" $ do
    let check :: HasCallStack => Bool -> Bool -> (Either String () -> Bool) -> Spec
        check withMatchingCreds withID expected =
          it (show (withMatchingCreds, withID)) $ do
            (privCreds, pubCreds) <- mkcrds withMatchingCreds
            signature <- runMonadSign $ renderLBS def <$> signRoot privCreds (doc withID)
            (verifyRoot pubCreds =<< signature) `shouldSatisfy` expected

        mkcrds, _mkcrdsReal, _mkcrdsCached :: Bool -> IO (SignPrivCreds, SignCreds)
        mkcrds = _mkcrdsCached

        _mkcrdsReal = \case
          True  -> mkSignCreds keysize
          False -> (,) <$> (fst <$> mkSignCreds keysize) <*> (snd <$> mkSignCreds keysize)
        keysize = 192  -- not long enough for security, but hopefully long enough for swift testing

        _mkcrdsCached = pure . \case
          True  -> (sampleIdPPrivkey, sampleIdPPubkey)
          False -> (sampleIdPPrivkey, sampleIdPPubkey2)

        someID withID = Map.fromList [("ID", UUID.toText UUID.nil) | withID]
        doc withID = Document (Prologue [] Nothing []) (Element "root" (someID withID) root) []
        root = [xml|
                  <bloo hign="___">
                    <ack hoghn="true">
                      <nonack>
                    hackach
                |]

    check True True (== Right ())
    check True False (== Right ())
    check False True isLeft
    check False False isLeft

    it "keeps data intact" $ do
      (privCreds, _pubCreds) <- mkcrds True
      Right outcome <- runMonadSign (cs . renderLBS def <$> signRoot privCreds (doc False))
      (outcome `shouldContain`) `mapM_` ["bloo", "ack", "hackach", "hackach"]

    it "honors non-0 signature position." $ do
      (privCreds, _pubCreds) <- mkcrds True
      Right signed <- runMonadSign $ signRootAt 1 privCreds (doc False)
      case signed of
        Document
          _
          (Element "root" _
            [ NodeElement (Element "bloo" _ _)
            , NodeElement (Element "{http://www.w3.org/2000/09/xmldsig#}Signature" _ _)
            ])
          _
          -> pure ()
        bad -> error $ show bad

    it "throws an error is signature position points outside the children list." $ do
      (privCreds, _pubCreds) <- mkcrds True
      outcome <- runMonadSign $ signRootAt 2 privCreds (doc False)
      outcome `shouldSatisfy` isLeft
