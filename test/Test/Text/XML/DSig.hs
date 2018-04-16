{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.Text.XML.DSig (tests) where

import Data.String.Conversions
import Test.Tasty
import Test.Tasty.HUnit
import Text.XML

import qualified Crypto.PubKey.RSA as RSA

import Test.Util
import Text.XML.DSig

import qualified Test.Samples


tests :: TestTree
tests = testGroup "xml:dsig"
  [ testGroup "key handling"
    [ testCase "parseKeyInfo" $ do
        let keyinfo = readXmlSample "microsoft-idp-keyinfo.xml"
            want = Test.Samples.microsoft_idp_keyinfo
        have <- parseKeyInfo keyinfo
        assertEqual "microsoft-idp-keyinfo.xml" have want

    , testCase "verify" $ do
        (_, el, vf) <- verificationSample
        assertEqual "..." (unverify vf) el

    , testCase "fmapVerify" $ do
        (_, _, vf) <- verificationSample
        let dothis = Element "NewRoot" mempty . (:[]) . NodeElement
            one = dothis . unverify
            two = unverify . fmapVerified dothis
        assertEqual "..." (one vf) (two vf)
    ]
  ]


verificationSample :: IO (RSA.PublicKey, Element, Verified Element)
verificationSample = do
  let key = Test.Samples.microsoft_idp_keyinfo
      Right (Document _ (el :: Element) _) =
        parseLBS def . cs $ readXmlSample "microsoft-signed-assertion.xml"
  vf <- verify key el
  pure (key, el, vf)
