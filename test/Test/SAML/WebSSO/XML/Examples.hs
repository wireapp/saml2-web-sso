{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes          #-}

{-# OPTIONS_GHC -Wno-unused-binds #-}

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

    , let -- source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference
          want = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
              <> "<samlp:AuthnRequest"
              <> "  ID=\"id6c1c178c166d486687be4aaf5e482730\""
              <> "  IssueInstant=\"2013-03-18T03:28:54.1839884Z\""
              <> "  Version=\"2.0\""
              <> "  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
              <> "    <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
              <> "        https://www.contoso.com"
              <> "    </Issuer>"
              <> "</samlp:AuthnRequest>"
          have = AuthnRequest
                   (ID "id6c1c178c166d486687be4aaf5e482730")
                   Version_2_0
                   (unsafeReadTime "2013-03-18T03:28:54.1839884Z")
                   (mkURI "https://www.contoso.com")
                   Nothing
      in roundtrip 0 want have

    , let  -- source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference
          want = "<samlp:Response"
              <> "  Destination=\"https://contoso.com/identity/inboundsso.aspx\""
              <> "  ID=\"_a4958bfd-e107-4e67-b06d-0d85ade2e76a\""
              <> "  InResponseTo=\"id758d0ef385634593a77bdf7e632984b6\""
              <> "  IssueInstant=\"2013-03-18T07:38:15.144Z\""
              <> "  Version=\"2.0\""
              <> "  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
              <> "    <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://login.microsoftonline.com/82869000-6ad1-48f0-8171-272ed18796e9/</Issuer>"
              <> "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">...</ds:Signature>"
              <> "    <samlp:Status>"
              <> "        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              <> "    </samlp:Status>"
              <> "    <Assertion"
              <> "      ID=\"_bf9c623d-cc20-407a-9a59-c2d0aee84d12\""
              <> "      IssueInstant=\"2013-03-18T07:38:15.144Z\""
              <> "      Version=\"2.0\""
              <> "      xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
              <> "        <Issuer>https://login.microsoftonline.com/82869000-6ad1-48f0-8171-272ed18796e9/</Issuer>"
              <> "        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">...</ds:Signature>"
              <> "        <Subject>"
              <> "            <NameID>Uz2Pqz1X7pxe4XLWxV9KJQ+n59d573SepSAkuYKSde8=</NameID>"
              <> "            <SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
              <> "                <SubjectConfirmationData"
              <> "                  InResponseTo=\"id758d0ef385634593a77bdf7e632984b6\""
              <> "                  NotOnOrAfter=\"2013-03-18T07:43:15.144Z\""
              <> "                  Recipient=\"https://contoso.com/identity/inboundsso.aspx\"/></SubjectConfirmation>"
              <> "        </Subject>"
              <> "        <Conditions NotBefore=\"2013-03-18T07:38:15.128Z\" NotOnOrAfter=\"2013-03-18T08:48:15.128Z\">"
              <> "            <AudienceRestriction><Audience>https://www.contoso.com</Audience></AudienceRestriction>"
              <> "        </Conditions>"
              <> "        <AttributeStatement>"
              <> "            <Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\">"
              <> "                <AttributeValue>testuser@contoso.com</AttributeValue>"
              <> "            </Attribute>"
              <> "            <Attribute Name=\"http://schemas.microsoft.com/identity/claims/objectidentifier\">"
              <> "                <AttributeValue>3F2504E0-4F89-11D3-9A0C-0305E82C3301</AttributeValue>"
              <> "            </Attribute>"
              <> "        </AttributeStatement>"
              <> "        <AuthnStatement AuthnInstant=\"2013-03-18T07:33:56Z\" SessionIndex=\"_bf9c623d-cc20-407a-9a59-c2d0aee84d12\">"
              <> "            <AuthnContext>"
              <> "                <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>"
              <> "            </AuthnContext>"
              <> "        </AuthnStatement>"
              <> "    </Assertion>"
              <> "</samlp:Response>"
          have = Response
            { _rspID = ID "_a4958bfd-e107-4e67-b06d-0d85ade2e76a"
            , _rspIssueInstant = unsafeReadTime "2013-03-18T07:38:15.144Z"
            , _rspInRespTo = ID "id758d0ef385634593a77bdf7e632984b6"
            , _rspDestination = Just
                URI
                  { uriScheme = Scheme { schemeBS = "https" }
                  , uriAuthority =
                      Just
                        Authority
                          { authorityUserInfo = Nothing
                          , authorityHost = Host { hostBS = "contoso.com" }
                          , authorityPort = Nothing
                          }
                  , uriPath = "/identity/inboundsso.aspx"
                  , uriQuery = Query { queryPairs = [] }
                  , uriFragment = Nothing
                  }
            , _rspVersion = Version_2_0
            , _rspIssuer = Just
                URI
                  { uriScheme = Scheme { schemeBS = "https" }
                  , uriAuthority =
                      Just
                        Authority
                          { authorityUserInfo = Nothing
                          , authorityHost = Host { hostBS = "login.microsoftonline.com" }
                          , authorityPort = Nothing
                          }
                  , uriPath = "/82869000-6ad1-48f0-8171-272ed18796e9/"
                  , uriQuery = Query { queryPairs = [] }
                  , uriFragment = Nothing
                  }
            , _rspStatus = StatusSuccess
            , _rspAssertion =
                [ Assertion
                    { _assVersion = Version_2_0
                    , _assID = ID "_bf9c623d-cc20-407a-9a59-c2d0aee84d12"
                    , _assIssueInstant = unsafeReadTime "2013-03-18T07:38:15.144Z"
                    , _assIssuer =
                        URI
                          { uriScheme = Scheme { schemeBS = "https" }
                          , uriAuthority =
                              Just
                                Authority
                                  { authorityUserInfo = Nothing
                                  , authorityHost = Host { hostBS = "login.microsoftonline.com" }
                                  , authorityPort = Nothing
                                  }
                          , uriPath = "/82869000-6ad1-48f0-8171-272ed18796e9/"
                          , uriQuery = Query { queryPairs = [] }
                          , uriFragment = Nothing
                          }
                    , _assConditions =
                        Conditions
                          { _condNotBefore = Just $ unsafeReadTime "2013-03-18T07:38:15.128Z"
                          , _condNotOnOrAfter = Just $ unsafeReadTime "2013-03-18T08:48:15.128Z"
                          , _condOneTimeUse = False
                          }
                    , _assContents =
                        SubjectAndStatements
                          Subject
                            { _subjectID =
                                Just
                                  (SubjectNameID
                                     (NameID "Uz2Pqz1X7pxe4XLWxV9KJQ+n59d573SepSAkuYKSde8="))
                            , _subjectConfirmations =
                                [ SubjectConfirmation
                                    { _scMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                                    , _scID = Nothing
                                    , _scData =
                                        [ SubjectConfirmationData
                                            { _scdNotBefore = Nothing
                                            , _scdNotOnOrAfter = Just (unsafeReadTime "2013-03-18T07:43:15.144Z")
                                            , _scdRecipient =
                                                Just
                                                  URI
                                                    { uriScheme = Scheme { schemeBS = "https" }
                                                    , uriAuthority =
                                                        Just
                                                          Authority
                                                            { authorityUserInfo = Nothing
                                                            , authorityHost = Host { hostBS = "contoso.com" }
                                                            , authorityPort = Nothing
                                                            }
                                                    , uriPath = "/identity/inboundsso.aspx"
                                                    , uriQuery = Query { queryPairs = [] }
                                                    , uriFragment = Nothing
                                                    }
                                            , _scdInResponseTo = Just (ID "id758d0ef385634593a77bdf7e632984b6")
                                            , _scdAddress = Nothing
                                            }
                                        ]
                                    }
                                ]
                            }
                          [ AuthnStatement
                              { _astAuthnInstant = unsafeReadTime "2013-03-18T07:33:56Z"
                              , _astSessionIndex = Just "_bf9c623d-cc20-407a-9a59-c2d0aee84d12"
                              , _astSessionNotOnOrAfter = Nothing
                              , _astSubjectLocality = Nothing
                              }
                          , AttributeStatement
                              { _attrstAttrs = undefined
                                  , Attribute
                                      { _stattrName =
                                          "http://schemas.microsoft.com/identity/claims/objectidentifier"
                                      , _stattrNameFormat = Nothing
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Nothing
                                                      }
                                                , elementAttributes = mempty
                                                , elementNodes =
                                                    [ NodeContent "3F2504E0-4F89-11D3-9A0C-0305E82C3301" ]
                                                }
                                          ]
                                      }
                                  ]
                              }
                          ]
                    }
                ]
            }
      in roundtrip 1 want have

    , ignoreTest $
      let want = cs . unsafePerformIO $ Prelude.readFile "test/xml/microsoft-meta-2.xml"
          have = EntityDescriptor
            { _edEntityID =
                "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/"
            , _edID = Just (ID "_e3a565aa-1392-4446-a4d6-3771453808f0")
            , _edValidUntil = Nothing
            , _edCacheDuration = Just Duration
            , _edExtensions = []
            , _edRoles =
                [ RoleRoleDescriptor
                    RoleDescriptor
                      { _rssoID = Nothing
                      , _rssoValidUntil = Nothing
                      , _rssoCacheDuration = Just Duration
                      , _rssoProtocolSupportEnumeration =
                          [ "http://docs.oasis-open.org/wsfed/federation/200706" ]
                      , _rssoErrorURL = Nothing
                      , _rssoKeyDescriptors =
                          [ KeyDescriptor
                              { _kdUse = Just KeyDescriptorEncryption
                              , _kdKeyInfo =
                                  Element
                                      { elementName =
                                          Name
                                            { nameLocalName = "KeyInfo"
                                            , nameNamespace = Just "http://www.w3.org/2000/09/xmldsig#"
                                            , namePrefix = Nothing
                                            }
                                      , elementAttributes = mempty
                                      , elementNodes =
                                          [ NodeElement
                                              Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "X509Data"
                                                      , nameNamespace =
                                                          Just "http://www.w3.org/2000/09/xmldsig#"
                                                      , namePrefix = Nothing
                                                      }
                                                , elementAttributes = mempty
                                                , elementNodes =
                                                    [ NodeElement
                                                        Element
                                                          { elementName =
                                                              Name
                                                                { nameLocalName = "X509Certificate"
                                                                , nameNamespace =
                                                                    Just
                                                                      "http://www.w3.org/2000/09/xmldsig#"
                                                                , namePrefix = Nothing
                                                                }
                                                          , elementAttributes = mempty
                                                          , elementNodes =
                                                              [ NodeContent
                                                                  "MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk"
                                                              ]
                                                          }
                                                    ]
                                                }
                                          ]
                                      }
                              , _kdEncryptionMethods = []
                              }
                          , KeyDescriptor
                              { _kdUse = Just KeyDescriptorEncryption
                              , _kdKeyInfo =
                                  Element
                                      { elementName =
                                          Name
                                            { nameLocalName = "KeyInfo"
                                            , nameNamespace = Just "http://www.w3.org/2000/09/xmldsig#"
                                            , namePrefix = Nothing
                                            }
                                      , elementAttributes = mempty
                                      , elementNodes =
                                          [ NodeElement
                                              Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "X509Data"
                                                      , nameNamespace =
                                                          Just "http://www.w3.org/2000/09/xmldsig#"
                                                      , namePrefix = Nothing
                                                      }
                                                , elementAttributes = mempty
                                                , elementNodes =
                                                    [ NodeElement
                                                        Element
                                                          { elementName =
                                                              Name
                                                                { nameLocalName = "X509Certificate"
                                                                , nameNamespace =
                                                                    Just
                                                                      "http://www.w3.org/2000/09/xmldsig#"
                                                                , namePrefix = Nothing
                                                                }
                                                          , elementAttributes = mempty
                                                          , elementNodes =
                                                              [ NodeContent
                                                                  "MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE="
                                                              ]
                                                          }
                                                    ]
                                                }
                                          ]
                                      }
                              , _kdEncryptionMethods = []
                              }
                          ]
                      }
                , RoleRoleDescriptor
                    RoleDescriptor
                      { _rssoID = Nothing
                      , _rssoValidUntil = Nothing
                      , _rssoCacheDuration = Just Duration
                      , _rssoProtocolSupportEnumeration =
                          [ "http://docs.oasis-open.org/wsfed/federation/200706" ]
                      , _rssoErrorURL = Nothing
                      , _rssoKeyDescriptors =
                          [ KeyDescriptor
                              { _kdUse = Just KeyDescriptorEncryption
                              , _kdKeyInfo =
                                  Element
                                      { elementName =
                                          Name
                                            { nameLocalName = "KeyInfo"
                                            , nameNamespace = Just "http://www.w3.org/2000/09/xmldsig#"
                                            , namePrefix = Nothing
                                            }
                                      , elementAttributes = mempty
                                      , elementNodes =
                                          [ NodeElement
                                              Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "X509Data"
                                                      , nameNamespace =
                                                          Just "http://www.w3.org/2000/09/xmldsig#"
                                                      , namePrefix = Nothing
                                                      }
                                                , elementAttributes = mempty
                                                , elementNodes =
                                                    [ NodeElement
                                                        Element
                                                          { elementName =
                                                              Name
                                                                { nameLocalName = "X509Certificate"
                                                                , nameNamespace =
                                                                    Just
                                                                      "http://www.w3.org/2000/09/xmldsig#"
                                                                , namePrefix = Nothing
                                                                }
                                                          , elementAttributes = mempty
                                                          , elementNodes =
                                                              [ NodeContent
                                                                  "MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk"
                                                              ]
                                                          }
                                                    ]
                                                }
                                          ]
                                      }
                              , _kdEncryptionMethods = []
                              }
                          , KeyDescriptor
                              { _kdUse = Just KeyDescriptorEncryption
                              , _kdKeyInfo =
                                  Element
                                      { elementName =
                                          Name
                                            { nameLocalName = "KeyInfo"
                                            , nameNamespace = Just "http://www.w3.org/2000/09/xmldsig#"
                                            , namePrefix = Nothing
                                            }
                                      , elementAttributes = mempty
                                      , elementNodes =
                                          [ NodeElement
                                              Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "X509Data"
                                                      , nameNamespace =
                                                          Just "http://www.w3.org/2000/09/xmldsig#"
                                                      , namePrefix = Nothing
                                                      }
                                                , elementAttributes = mempty
                                                , elementNodes =
                                                    [ NodeElement
                                                        Element
                                                          { elementName =
                                                              Name
                                                                { nameLocalName = "X509Certificate"
                                                                , nameNamespace =
                                                                    Just
                                                                      "http://www.w3.org/2000/09/xmldsig#"
                                                                , namePrefix = Nothing
                                                                }
                                                          , elementAttributes = mempty
                                                          , elementNodes =
                                                              [ NodeContent
                                                                  "MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE="
                                                              ]
                                                          }
                                                    ]
                                                }
                                          ]
                                      }
                              , _kdEncryptionMethods = []
                              }
                          ]
                      }
                , RoleIDPSSODescriptor
                    IDPSSODescriptor
                      { _idpWantAuthnRequestsSigned = False
                      , _idpSingleSignOnService =
                          EndPoint
                            { _epBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            , _epLocation =
                                URI
                                  { uriScheme = Scheme { schemeBS = "https" }
                                  , uriAuthority =
                                      Just
                                        Authority
                                          { authorityUserInfo = Nothing
                                          , authorityHost = Host { hostBS = "login.microsoftonline.com" }
                                          , authorityPort = Nothing
                                          }
                                  , uriPath = "/682febe8-021b-4fde-ac09-e60085f05181/saml2"
                                  , uriQuery = Query { queryPairs = [] }
                                  , uriFragment = Nothing
                                  }
                            , _epResponseLocation = ()
                            } :|
                            [ EndPoint
                                { _epBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                , _epLocation =
                                    URI
                                      { uriScheme = Scheme { schemeBS = "https" }
                                      , uriAuthority =
                                          Just
                                            Authority
                                              { authorityUserInfo = Nothing
                                              , authorityHost =
                                                  Host { hostBS = "login.microsoftonline.com" }
                                              , authorityPort = Nothing
                                              }
                                      , uriPath = "/682febe8-021b-4fde-ac09-e60085f05181/saml2"
                                      , uriQuery = Query { queryPairs = [] }
                                      , uriFragment = Nothing
                                      }
                                , _epResponseLocation = ()
                                }
                            ]
                      , _idNameIDMappingService = []
                      , _idAssertionIDRequestService = []
                      , _idAttributeProfile = []
                      }
                ]
            }
      in roundtrip 2 want have

    , ignoreTest $
      let want = cs . unsafePerformIO $ Prelude.readFile "test/xml/onelogin-request-1.xml"
          have = AuthnRequest
            { _rqID = ID "pfx41d8ef22-e612-8c50-9960-1b16f15741b3"
            , _rqVersion = Version_2_0
            , _rqIssueInstant = unsafeReadTime "2014-07-16T23:52:45Z"
            , _rqIssuer =
                URI
                  { uriScheme = Scheme { schemeBS = "http" }
                  , uriAuthority =
                      Just
                        Authority
                          { authorityUserInfo = Nothing
                          , authorityHost = Host { hostBS = "sp.example.com" }
                          , authorityPort = Nothing
                          }
                  , uriPath = "/demo1/metadata.php"
                  , uriQuery = Query { queryPairs = [] }
                  , uriFragment = Nothing
                  }
            , _rqDestination = Just $ mkURI "http://idp.example.com/SSOService.php"
            }
      in roundtrip 3 want have

    , ignoreTest $
      let want = cs . unsafePerformIO $ Prelude.readFile "test/xml/onelogin-response-1.xml"
          have = Response
            { _rspID = ID "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
            , _rspInRespTo =
                ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
            , _rspVersion = Version_2_0
            , _rspIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
            , _rspDestination =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "sp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/demo1/index.php"
                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                    , uriFragment = Nothing
                    }
            , _rspIssuer =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "idp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/metadata.php"
                    , uriQuery = Query { queryPairs = [] }
                    , uriFragment = Nothing
                    }
            , _rspStatus = StatusSuccess
            , _rspAssertion =
                [ Assertion
                    { _assVersion = Version_2_0
                    , _assID = ID "pfxbed3e5c2-7d30-4bbe-bb78-f967b463f43b"
                    , _assIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                    , _assIssuer =
                        URI
                          { uriScheme = Scheme { schemeBS = "http" }
                          , uriAuthority =
                              Just
                                Authority
                                  { authorityUserInfo = Nothing
                                  , authorityHost = Host { hostBS = "idp.example.com" }
                                  , authorityPort = Nothing
                                  }
                          , uriPath = "/metadata.php"
                          , uriQuery = Query { queryPairs = [] }
                          , uriFragment = Nothing
                          }
                    , _assConditions =
                        Conditions
                          { _condNotBefore = Just $ unsafeReadTime "2014-07-17T01:01:18Z"
                          , _condNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                          , _condOneTimeUse = False
                          }
                    , _assContents =
                        SubjectAndStatements
                          Subject
                            { _subjectID =
                                Just
                                  (SubjectNameID
                                     (NameID "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"))
                            , _subjectConfirmations =
                                [ SubjectConfirmation
                                    { _scMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                                    , _scID = Nothing
                                    , _scData =
                                        [ SubjectConfirmationData
                                            { _scdNotBefore = Nothing
                                            , _scdNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                                            , _scdRecipient =
                                                Just
                                                  URI
                                                    { uriScheme = Scheme { schemeBS = "http" }
                                                    , uriAuthority =
                                                        Just
                                                          Authority
                                                            { authorityUserInfo = Nothing
                                                            , authorityHost =
                                                                Host { hostBS = "sp.example.com" }
                                                            , authorityPort = Nothing
                                                            }
                                                    , uriPath = "/demo1/index.php"
                                                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                                                    , uriFragment = Nothing
                                                    }
                                            , _scdInResponseTo =
                                                Just
                                                  (ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")
                                            , _scdAddress = Nothing
                                            }
                                        ]
                                    }
                                ]
                            }
                          [ AuthnStatement
                              { _astAuthnInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                              , _astSessionIndex =
                                  Just "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"
                              , _astSessionNotOnOrAfter = Just $ unsafeReadTime "2024-07-17T09:01:48Z"
                              , _astSubjectLocality = Nothing
                              }
                          , AttributeStatement
                              { _attrstAttrs =
                                  [ Attribute
                                      { _stattrName = "uid"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "mail"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test@example.com" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "eduPersonAffiliation"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "users" ]
                                                }
                                          , Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "examplerole1" ]
                                                }
                                          ]
                                      }
                                  ]
                              }
                          ]
                    }
                ]
            }
      in roundtrip 4 want have

    , ignoreTest $
      let want = cs . unsafePerformIO $ Prelude.readFile "test/xml/onelogin-response-2.xml"
          have = Response
            { _rspID = ID "pfxc2d8baa7-8ebb-dfdd-740a-27145e760815"
            , _rspInRespTo =
                ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
            , _rspVersion = Version_2_0
            , _rspIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
            , _rspDestination =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "sp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/demo1/index.php"
                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                    , uriFragment = Nothing
                    }
            , _rspIssuer =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "idp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/metadata.php"
                    , uriQuery = Query { queryPairs = [] }
                    , uriFragment = Nothing
                    }
            , _rspStatus = StatusSuccess
            , _rspAssertion =
                [ Assertion
                    { _assVersion = Version_2_0
                    , _assID = ID "_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"
                    , _assIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                    , _assIssuer =
                        URI
                          { uriScheme = Scheme { schemeBS = "http" }
                          , uriAuthority =
                              Just
                                Authority
                                  { authorityUserInfo = Nothing
                                  , authorityHost = Host { hostBS = "idp.example.com" }
                                  , authorityPort = Nothing
                                  }
                          , uriPath = "/metadata.php"
                          , uriQuery = Query { queryPairs = [] }
                          , uriFragment = Nothing
                          }
                    , _assConditions =
                        Conditions
                          { _condNotBefore = Just $ unsafeReadTime "2014-07-17T01:01:18Z"
                          , _condNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                          , _condOneTimeUse = False
                          }
                    , _assContents =
                        SubjectAndStatements
                          Subject
                            { _subjectID =
                                Just
                                  (SubjectNameID
                                     (NameID "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"))
                            , _subjectConfirmations =
                                [ SubjectConfirmation
                                    { _scMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                                    , _scID = Nothing
                                    , _scData =
                                        [ SubjectConfirmationData
                                            { _scdNotBefore = Nothing
                                            , _scdNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                                            , _scdRecipient =
                                                Just
                                                  URI
                                                    { uriScheme = Scheme { schemeBS = "http" }
                                                    , uriAuthority =
                                                        Just
                                                          Authority
                                                            { authorityUserInfo = Nothing
                                                            , authorityHost =
                                                                Host { hostBS = "sp.example.com" }
                                                            , authorityPort = Nothing
                                                            }
                                                    , uriPath = "/demo1/index.php"
                                                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                                                    , uriFragment = Nothing
                                                    }
                                            , _scdInResponseTo =
                                                Just
                                                  (ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")
                                            , _scdAddress = Nothing
                                            }
                                        ]
                                    }
                                ]
                            }
                          [ AuthnStatement
                              { _astAuthnInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                              , _astSessionIndex =
                                  Just "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"
                              , _astSessionNotOnOrAfter = Just $ unsafeReadTime "2024-07-17T09:01:48Z"
                              , _astSubjectLocality = Nothing
                              }
                          , AttributeStatement
                              { _attrstAttrs =
                                  [ Attribute
                                      { _stattrName = "uid"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "mail"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test@example.com" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "eduPersonAffiliation"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "users" ]
                                                }
                                          , Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "examplerole1" ]
                                                }
                                          ]
                                      }
                                  ]
                              }
                          ]
                    }
                ]
            }
      in roundtrip 5 want have

    , ignoreTest $
      let want = cs . unsafePerformIO $ Prelude.readFile "test/xml/onelogin-response-3.xml"
          have = Response
            { _rspID = ID "pfxcf6b8eff-4eb4-7d62-a304-8a227b0c5205"
            , _rspInRespTo =
                ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
            , _rspVersion = Version_2_0
            , _rspIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
            , _rspDestination =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "sp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/demo1/index.php"
                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                    , uriFragment = Nothing
                    }
            , _rspIssuer =
                Just
                  URI
                    { uriScheme = Scheme { schemeBS = "http" }
                    , uriAuthority =
                        Just
                          Authority
                            { authorityUserInfo = Nothing
                            , authorityHost = Host { hostBS = "idp.example.com" }
                            , authorityPort = Nothing
                            }
                    , uriPath = "/metadata.php"
                    , uriQuery = Query { queryPairs = [] }
                    , uriFragment = Nothing
                    }
            , _rspStatus = StatusSuccess
            , _rspAssertion =
                [ Assertion
                    { _assVersion = Version_2_0
                    , _assID = ID "pfxa0034489-8445-2acc-e341-41f7029a5aaf"
                    , _assIssueInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                    , _assIssuer =
                        URI
                          { uriScheme = Scheme { schemeBS = "http" }
                          , uriAuthority =
                              Just
                                Authority
                                  { authorityUserInfo = Nothing
                                  , authorityHost = Host { hostBS = "idp.example.com" }
                                  , authorityPort = Nothing
                                  }
                          , uriPath = "/metadata.php"
                          , uriQuery = Query { queryPairs = [] }
                          , uriFragment = Nothing
                          }
                    , _assConditions =
                        Conditions
                          { _condNotBefore = Just $ unsafeReadTime "2014-07-17T01:01:18Z"
                          , _condNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                          , _condOneTimeUse = False
                          }
                    , _assContents =
                        SubjectAndStatements
                          Subject
                            { _subjectID =
                                Just
                                  (SubjectNameID
                                     (NameID "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"))
                            , _subjectConfirmations =
                                [ SubjectConfirmation
                                    { _scMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                                    , _scID = Nothing
                                    , _scData =
                                        [ SubjectConfirmationData
                                            { _scdNotBefore = Nothing
                                            , _scdNotOnOrAfter = Just $ unsafeReadTime "2024-01-18T06:21:48Z"
                                            , _scdRecipient =
                                                Just
                                                  URI
                                                    { uriScheme = Scheme { schemeBS = "http" }
                                                    , uriAuthority =
                                                        Just
                                                          Authority
                                                            { authorityUserInfo = Nothing
                                                            , authorityHost =
                                                                Host { hostBS = "sp.example.com" }
                                                            , authorityPort = Nothing
                                                            }
                                                    , uriPath = "/demo1/index.php"
                                                    , uriQuery = Query { queryPairs = [ ( "acs" , "" ) ] }
                                                    , uriFragment = Nothing
                                                    }
                                            , _scdInResponseTo =
                                                Just
                                                  (ID "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")
                                            , _scdAddress = Nothing
                                            }
                                        ]
                                    }
                                ]
                            }
                          [ AuthnStatement
                              { _astAuthnInstant = unsafeReadTime "2014-07-17T01:01:48Z"
                              , _astSessionIndex =
                                  Just "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"
                              , _astSessionNotOnOrAfter = Just $ unsafeReadTime "2024-07-17T09:01:48Z"
                              , _astSubjectLocality = Nothing
                              }
                          , AttributeStatement
                              { _attrstAttrs =
                                  [ Attribute
                                      { _stattrName = "uid"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "mail"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "test@example.com" ]
                                                }
                                          ]
                                      }
                                  , Attribute
                                      { _stattrName = "eduPersonAffiliation"
                                      , _stattrNameFormat =
                                          Just "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                                      , _stattrFriendlyName = Nothing
                                      , _stattrValue =
                                          [ Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "users" ]
                                                }
                                          , Element
                                                { elementName =
                                                    Name
                                                      { nameLocalName = "AttributeValue"
                                                      , nameNamespace =
                                                          Just "urn:oasis:names:tc:SAML:2.0:assertion"
                                                      , namePrefix = Just "saml"
                                                      }
                                                , elementAttributes =
                                                    Map.fromList
                                                      [ ( Name
                                                            { nameLocalName = "type"
                                                            , nameNamespace =
                                                                Just
                                                                  "http://www.w3.org/2001/XMLSchema-instance"
                                                            , namePrefix = Just "xsi"
                                                            }
                                                        , "xs:string"
                                                        )
                                                      ]
                                                , elementNodes = [ NodeContent "examplerole1" ]
                                                }
                                          ]
                                      }
                                  ]
                              }
                          ]
                    }
                ]
            }
      in roundtrip 6 want have
    ]
  ]
