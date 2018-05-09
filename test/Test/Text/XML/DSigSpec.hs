{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.Text.XML.DSigSpec (spec) where

import Data.String.Conversions
import Test.Hspec
import Text.XML

import qualified Crypto.PubKey.RSA as RSA

import Util
import Text.XML.DSig

import qualified Samples


spec :: Spec
spec = describe "xml:dsig" $ do
  describe "key handling" $ do
    it "parseKeyInfo" $ do
      let keyinfo = readXmlSample "microsoft-idp-keyinfo.xml"
          want = Samples.microsoft_idp_keyinfo
      have <- parseKeyInfo keyinfo
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
    it "..." $ do
      pending

      -- simpleVerifyAuthnResponse


verificationSample :: IO (RSA.PublicKey, Element, Verified Element)
verificationSample = do
  let key = Samples.microsoft_idp_keyinfo
      Right (Document _ (el :: Element) _) =
        parseLBS def . cs $ readXmlSample "microsoft-signed-assertion.xml"
  vf <- verify key el
  pure (key, el, vf)
