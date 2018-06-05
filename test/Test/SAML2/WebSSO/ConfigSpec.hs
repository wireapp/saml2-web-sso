{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML2.WebSSO.ConfigSpec (spec) where

import Arbitrary
import Data.Aeson
import Data.Aeson.Types
import Data.List.NonEmpty
import Data.String.Conversions
import Hedgehog
import SAML2.WebSSO
import Test.Hspec
import Text.XML.DSig
import Text.XML.Util
import Util

import qualified Data.Yaml as Yaml
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range


spec :: Spec
spec = describe "Config" $ do
  hedgehog . checkParallel . Group "roundtrip" $
    [("...", property $ forAll (genConfig (pure ())) >>= \v -> tripping v toJSON (parseEither parseJSON))]

  it "sample config" $ do
    want <- readSampleIO "server-config.yaml"
    let have :: Config_
        have = Config
          { _cfgVersion  = Version_2_0
          , _cfgLogLevel = DEBUG
          , _cfgSPHost   = "me.wire.com"
          , _cfgSPPort   = 443
          , _cfgSPAppURI = unsafeParseURI "https://me.wire.com/sp"
          , _cfgSPSsoURI = unsafeParseURI "https://me.wire.com/sso"
          , _cfgContacts = fallbackContact :| []
          , _cfgIdps =
            [ IdPConfig
              { _idpPath       = "azure-test"
              , _idpMetadata   = unsafeParseURI "https://login.microsoftonline.com/682febe8-021b-4fde-ac09-e60085f05181/FederationMetadata/2007-06/FederationMetadata.xml"
              , _idpIssuer     = mkIssuer "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/"
              , _idpRequestUri = unsafeParseURI "https://login.microsoftonline.com/682febe8-021b-4fde-ac09-e60085f05181/saml2"
              , _idpPublicKey  = either (error . show) id $ parseKeyInfo "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk</X509Certificate></X509Data></KeyInfo>"
              , _idpExtraInfo  = Nothing
              }
            ]
          }
    Yaml.decodeEither (cs want) `shouldBe` Right have


genConfig :: Gen extra -> Gen (Config extra)
genConfig genextra = do
  _cfgVersion    <- genVersion
  _cfgLogLevel   <- Gen.enumBounded
  _cfgSPHost     <- cs <$> genNiceWord
  _cfgSPPort     <- Gen.int (Range.linear 1 9999)
  _cfgSPAppURI   <- genURI
  _cfgSPSsoURI   <- genURI
  _cfgContacts   <- (:|) <$> genSPContactPerson <*> Gen.list (Range.linear 0 3) genSPContactPerson
  _cfgIdps       <- pure mempty
  _cfgExtraInfo  <- Gen.maybe genextra
  pure Config{..}

genSPContactPerson :: Gen SPContactPerson
genSPContactPerson = SPContactPerson
  <$> genNiceWord
  <*> genNiceWord
  <*> genNiceWord
  <*> genURI
  <*> genNiceWord
