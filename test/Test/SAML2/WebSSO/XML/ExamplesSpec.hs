{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-unused-imports #-}

module Test.SAML2.WebSSO.XML.ExamplesSpec (spec) where

import Control.Exception
import Control.Monad (forM_)
import Control.Monad.IO.Class (liftIO)
import Data.Either
import Data.List.NonEmpty as NL
import Data.String.Conversions
import SAML2.WebSSO
import System.Environment (setEnv)
import System.IO.Unsafe (unsafePerformIO)
import Test.Hspec
import Text.Show.Pretty (ppShow)
import Text.XML
import Text.XML.DSig as DSig
import Text.XML.Util
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

    roundtrip 0 (readSampleIO "microsoft-authnrequest-1.xml") Samples.microsoft_authnrequest_1
    -- roundtrip 1 (readSample "microsoft-authnresponse-0.xml") Samples.microsoft_authnresponse_0
    -- roundtrip 2 (readSample "microsoft-authnresponse-1.xml") Samples.microsoft_authnresponse_1
    -- roundtrip 3 (readSample "microsoft-authnresponse-2.xml") Samples.microsoft_authnresponse_2
    -- roundtrip 4 (readSample "microsoft-meta-2.xml") Samples.microsoft_meta_2
    -- roundtrip 5 (readSample "onelogin-request-1.xml") Samples.onelogin_request_1
    -- roundtrip 6 (readSample "onelogin-response-1.xml") (undefined :: AuthnResponse)
    -- roundtrip 7 (readSample "onelogin-response-2.xml") (undefined :: AuthnResponse)
    -- roundtrip 8 (readSample "onelogin-response-3.xml") (undefined :: AuthnResponse)

  describe "AuthnRequest" $ do
    it "works" $ do
      let req = AuthnRequest
            { _rqID = ID "aiandama aiandama"
            , _rqVersion = Version_2_0
            , _rqIssueInstant = unsafeReadTime "2013-03-18T07:33:56Z"
            , _rqIssuer = iss
            }
          iss = Issuer $ unsafeParseURI "http://wire.com"
      decodeElem @Issuer @(Either String) (encodeElem iss) `shouldBe` Right iss
      decodeElem @AuthnRequest @(Either String) (encodeElem req) `shouldBe` Right req


  describe "centrify AuthnResponse" $ do
      -- (this blob is just to demonstrate that centrify responses can be parsed; should be a
      -- simple roundtrip once we're done fixing things, except for the encoding.)

      it @Expectation "parse succeeds" . liftIO $ do
        base64raw :: LT <- readSampleIO "centrify-response-1.base64"

        pendingWith "Issuer URL is 'Centrify', which isn't a valid URL.  Need to get a correct response doc first."
        let Right (xmlraw :: LBS)
                = EL.decode
                . cs @String @LBS
                . List.filter (`notElem` ("\r\n" :: [Char]))
                . cs @LT @String
                $ base64raw
            Right (xmldoc :: Document) = parseText def $ cs xmlraw
            Right (saml2doc :: AuthnResponse) = parseFromDocument xmldoc

            have = cs xmlraw :: LT
            want = undefined :: AuthnResponse

        -- print base64raw
        -- print xmlraw
        -- putStrLn (ppShow xmldoc)
        parseFromDocument @AuthnResponse @(Either String) xmldoc `shouldSatisfy` isRight
        -- putStrLn (ppShow saml2doc)

      -- roundtrip 9 have want

  describe "microsoft IdPDesc" $ do
      it "works" $ do
        raw :: LT <- readSampleIO "microsoft-meta-2.xml"
        _edIssuer     <- either (error . show) (pure . Issuer) $ parseURI' "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/"
        _edRequestURI <- either (error . show) pure $ parseURI' "https://login.microsoftonline.com/682febe8-021b-4fde-ac09-e60085f05181/saml2"
        _edCertAuthnResponse <- either (error . show) (pure . NL.fromList) $ DSig.parseKeyInfo `mapM`
          [ "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk</X509Certificate></X509Data></KeyInfo>"
          , "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate></X509Data></KeyInfo>"
          ]
        decode raw `shouldBe` Right (IdPMetadata {..})
