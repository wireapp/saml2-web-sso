{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-unused-imports #-}

module Test.SAML.WebSSO.XML.ExamplesSpec (spec) where

import Control.Exception
import Text.Show.Pretty (ppShow)
import Control.Monad (forM_)
import Control.Monad.IO.Class (liftIO)
import Data.Either
import Data.List.NonEmpty
import Data.String.Conversions
import SAML.WebSSO
import System.Environment (setEnv)
import System.IO.Unsafe (unsafePerformIO)
import Test.Hspec
import Text.XML
import URI.ByteString
import Util

import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.List as List
import qualified Data.Map as Map
import qualified Samples


spec :: Spec
spec = describe "XML serialization" $ do
  describe "unit tests" $ do
    it "Time seconds have no more than 7 decimal digits" $ do
      --  (or else azure/AD will choke on it with a very useless error message)
      renderTime (unsafeReadTime "2013-03-18T03:28:54.1839884Z") `shouldBe`
        renderTime (unsafeReadTime "2013-03-18T03:28:54.18398841817Z")

      let decimalses = dot <$> List.inits "1839884181781"
            where
              dot "" = ""
              dot s = '.':s

      forM_ decimalses $ \decimals -> do
        let bad  = "2013-03-18T03:28:54" <> decimals <> "Z"
            good = "2013-03-18T03:28:54" <> List.take 8 decimals <> "Z"
        renderTime (unsafeReadTime good) `shouldBe` renderTime (unsafeReadTime bad)

    roundtrip 0 (readSample "microsoft-authnrequest-1.xml") Samples.microsoft_authnrequest_1
    -- roundtrip 1 (readSample "microsoft-authnresponse-0.xml") Samples.microsoft_authnresponse_0
    -- roundtrip 2 (readSample "microsoft-authnresponse-1.xml") Samples.microsoft_authnresponse_1
    -- roundtrip 3 (readSample "microsoft-authnresponse-2.xml") Samples.microsoft_authnresponse_2
    -- roundtrip 4 (readSample "microsoft-meta-2.xml") Samples.microsoft_meta_2
    -- roundtrip 5 (readSample "onelogin-request-1.xml") Samples.onelogin_request_1
    -- roundtrip 6 (readSample "onelogin-response-1.xml") (undefined :: AuthnResponse)
    -- roundtrip 7 (readSample "onelogin-response-2.xml") (undefined :: AuthnResponse)
    -- roundtrip 8 (readSample "onelogin-response-3.xml") (undefined :: AuthnResponse)

    describe "centrify" $ do
      -- (this blob is just to demonstrate that centrify responses can be parsed; should be a
      -- simple roundtrip once we're done fixing things, except for the encoding.)

      let base64raw :: LT = readSample "centrify-response-1.base64"

          Right (xmlraw :: LBS)
              = EL.decode
              . cs @String @LBS
              . List.filter (`notElem` ("\r\n" :: [Char]))
              . cs @LT @String
              $ base64raw
          Right (xmldoc :: Document) = parseText def $ cs xmlraw
          Right (saml2doc :: AuthnResponse) = parseFromDocument xmldoc

          have = cs xmlraw :: LT
          want = undefined :: AuthnResponse

      it @Expectation "parse succeeds" . liftIO $ do
        -- print base64raw
        -- print xmlraw
        -- putStrLn (ppShow xmldoc)
        parseFromDocument @AuthnResponse @(Either SomeException) xmldoc `shouldSatisfy` isRight
        -- putStrLn (ppShow saml2doc)

      -- roundtrip 9 have want
