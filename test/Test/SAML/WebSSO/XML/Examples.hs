{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-unused-imports #-}

module Test.SAML.WebSSO.XML.Examples (tests) where

import Text.Show.Pretty (ppShow)
import Control.Monad (forM_)
import Control.Monad.IO.Class (liftIO)
import Data.List.NonEmpty
import Data.String.Conversions
import SAML.WebSSO
import System.Environment (setEnv)
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty
import Test.Tasty.ExpectedFailure (ignoreTest)
import Test.Tasty.HUnit
import Text.XML
import URI.ByteString
import Util

import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.List as List
import qualified Data.Map as Map
import qualified Samples


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

    , let have = readXmlSample "microsoft-authnrequest-1.xml"
          want = Samples.microsoft_authnrequest_1
      in roundtrip 0 have want

    , ignoreTest $
      let have = readXmlSample "microsoft-authnresponse-0.xml"
          want = Samples.microsoft_authnresponse_0
      in roundtrip 1 have want

    , ignoreTest $
      let have = readXmlSample "microsoft-authnresponse-1.xml"
          want = Samples.microsoft_authnresponse_1
      in roundtrip 2 have want

    , ignoreTest $
      let have = readXmlSample "microsoft-authnresponse-2.xml"
          want = Samples.microsoft_authnresponse_2
      in roundtrip 3 have want

    , ignoreTest $
      let have = readXmlSample "microsoft-meta-2.xml"
          want = Samples.microsoft_meta_2
      in roundtrip 4 have want

    , ignoreTest $
      let have = readXmlSample "onelogin-request-1.xml"
          want = Samples.onelogin_request_1
      in roundtrip 5 have want

    , ignoreTest $
      let have = readXmlSample "onelogin-response-1.xml"
          want = undefined :: AuthnResponse
      in roundtrip 6 have want

    , ignoreTest $
      let have = readXmlSample "onelogin-response-2.xml"
          want = undefined :: AuthnResponse
      in roundtrip 7 have want

    , ignoreTest $
      let have = readXmlSample "onelogin-response-3.xml"
          want = undefined :: AuthnResponse
      in roundtrip 8 have want

    , ignoreTest $
      let base64raw :: LT = readXmlSample "centrify-response-1.base64"

          -- (this blob is just to demonstrate that centrify responses can be parsed; should be a
          -- simple roundtrip once we're done fixing things.)

          Right (xmlraw :: LBS)
              = EL.decode
              . cs @String @LBS
              . List.filter (`notElem` ("\r\n" :: [Char]))
              . cs @LT @String
              $ base64raw
          Right (xmldoc :: Document) = parseText def $ cs xmlraw
          Right (saml2doc :: AuthnRequest) = parseFromDocument xmldoc

          have = cs xmlraw :: LT
          want = undefined :: AuthnResponse

      in testGroup "centrify"
         [ testCase "response-1" . liftIO $ do
             print base64raw
             print xmlraw
             putStrLn (ppShow xmldoc)
             putStrLn (ppShow saml2doc)
         , roundtrip 9 have want
         ]
    ]
  ]
