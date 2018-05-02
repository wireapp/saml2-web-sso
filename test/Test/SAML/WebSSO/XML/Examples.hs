{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-unused-imports #-}

module Test.SAML.WebSSO.XML.Examples (tests) where

import Control.Monad (forM_)
import Data.List.NonEmpty
import qualified Data.List as List
import qualified Data.Map as Map
import Data.String.Conversions
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.ExpectedFailure (ignoreTest)
import Text.XML
import URI.ByteString

import Test.Util
import qualified Test.Samples
import SAML.WebSSO


tests :: TestTree
tests = testGroup "XML serialization"
  [ testGroup "unit tests"
    [ testCase "Time seconds have no more than 7 decimal digits" $ do
        --  (or else azure/AD will choke on it with a very useless error message)
        assertEqual "failed"
          (renderTime $ unsafeReadTime "2013-03-18T03:28:54.1839884Z")
          (renderTime $ unsafeReadTime "2013-03-18T03:28:54.18398841817Z")

        let decimalses = dot <$> List.inits "1839884181781"
              where
                dot "" = ""
                dot s = '.':s

        forM_ decimalses $ \decimals -> do
          let bad  = "2013-03-18T03:28:54" <> decimals <> "Z"
              good = "2013-03-18T03:28:54" <> List.take 8 decimals <> "Z"
          assertEqual "failed"
            (renderTime $ unsafeReadTime good)
            (renderTime $ unsafeReadTime bad)

    , let want = readXmlSample "microsoft-authnrequest-1.xml"
          have = Test.Samples.microsoft_authnrequest_1
      in roundtrip 0 want have

    , ignoreTest $
      let want = readXmlSample "microsoft-authnresponse-0.xml"
          have = Test.Samples.microsoft_authnresponse_0
      in roundtrip 1 want have

    , ignoreTest $
      let want = readXmlSample "microsoft-authnresponse-1.xml"
          have = Test.Samples.microsoft_authnresponse_1
      in roundtrip 2 want have

    , ignoreTest $
      let want = readXmlSample "microsoft-authnresponse-2.xml"
          have = Test.Samples.microsoft_authnresponse_2
      in roundtrip 3 want have

    , ignoreTest $
      let want = readXmlSample "microsoft-meta-2.xml"
          have = Test.Samples.microsoft_meta_2
      in roundtrip 4 want have

    , ignoreTest $
      let want = readXmlSample "onelogin-request-1.xml"
          have = Test.Samples.onelogin_request_1
      in roundtrip 5 want have

    , ignoreTest $
      let want = readXmlSample "onelogin-response-1.xml"
          have = undefined :: AuthnResponse
      in roundtrip 6 want have

    , ignoreTest $
      let want = readXmlSample "onelogin-response-2.xml"
          have = undefined :: AuthnResponse
      in roundtrip 7 want have

    , ignoreTest $
      let want = readXmlSample "onelogin-response-3.xml"
          have = undefined :: AuthnResponse
      in roundtrip 8 want have
    ]
  ]
