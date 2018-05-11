{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Data.Either
import Data.String.Conversions
import Test.Hspec
import Text.XML

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.X509 as X509

import Util
import Text.XML.DSig

import qualified Samples


spec :: Spec
spec = describe "xml:dsig" $ do
  describe "key handling" $ do
    it "parseKeyInfo" $ do
      let keyinfo = readSample "microsoft-idp-keyinfo.xml"
          want = Samples.microsoft_idp_keyinfo
          Right (SignCreds _ (SignKeyRSA have)) = keyInfoToCreds =<< parseKeyInfo keyinfo
      have `shouldBe` want

  describe "verify" $ do
    it "verify" $ do
      (_, el, vf) <- verificationSample
      unverify vf `shouldBe` el

    it "fmapVerify" $ do
      (_, _, vf) <- verificationSample
      let dothis = Element "NewRoot" mempty . (:[]) . NodeElement
          one = dothis . unverify
          two = unverify . fmapVerified dothis
      one vf `shouldBe` two vf

  describe "simpleVerifyAuthnResponse" $ do
    let check goodsig knownkey expectOutcome =
          it (show expectOutcome) $ do
            let respfile = if goodsig
                  then "microsoft-authnresponse-2.xml"
                  else "microsoft-authnresponse-2-badsig.xml"

            resp :: LBS <- cs <$> readSampleIO respfile
            Right (cert :: X509.SignedCertificate) <- parseKeyInfo <$> readSampleIO "microsoft-idp-keyinfo.xml"
            let Right (SignCreds _ (SignKeyRSA (key :: RSA.PublicKey))) = keyInfoToCreds cert

            let lookupKey :: ST -> Maybe RSA.PublicKey
                lookupKey "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/" | knownkey = Just key
                lookupKey _ = Nothing

                go :: Either String ()
                go = simpleVerifyAuthnResponse lookupKey resp

            if expectOutcome
              then go `shouldBe` Right ()
              else go `shouldSatisfy` isLeft

    context "good signature" $ do
      context "known key"    $ check True True True
      context "unknown key"  $ check True False False

    context "bad signature"  $ do
      context "known key"    $ check False True False
      context "unknown key"  $ check False False False


verificationSample :: IO (RSA.PublicKey, Element, Verified Element)
verificationSample = do
  let key = Samples.microsoft_idp_keyinfo
      Right (Document _ (el :: Element) _) =
        parseLBS def . cs $ readSample "microsoft-signed-assertion.xml"
  vf <- verifyIO key el
  pure (key, el, vf)
