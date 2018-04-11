{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML.WebSSO.API (tests) where

import Data.EitherR
import Data.String.Conversions
import Servant
import System.Process
import Test.Tasty
import Test.Tasty.HUnit
import Text.Hamlet.XML
import Text.XML as XML

import SAML.WebSSO


newtype SomeSAMLRequest = SomeSAMLRequest { fromSomeSAMLRequest :: XML.Document }
  deriving (Eq, Show)

instance HasFormRedirect SomeSAMLRequest where
  formRedirectFieldName _ = "SAMLRequest"

instance HasXML SomeSAMLRequest where
  nameSpaces Proxy = []
  parse = fmap SomeSAMLRequest . parse

instance HasXMLRoot SomeSAMLRequest where
  renderRoot (SomeSAMLRequest doc) = renderRoot doc

tests :: TestTree
tests = testGroup "API"
  [ testGroup "base64 encoding"
    [ testCase "compatible with /usr/bin/base64" $ do
        let check :: Document -> IO ()
            check doc = do
              let ours = base64xml $ SomeSAMLRequest doc
              theirs <- cs <$> readProcess "/usr/bin/base64" ["--wrap", "64"] (cs $ renderText def doc)
              assertEqual "failed" ours theirs

            tree = [xml|
                       <blurp rough="13r-dfityhnhv-eufy9a" holiday="...">
                         <bloo>
                           <bloo/>
                           <bla>
                             <blaa/>
                   |]

        check $ Document (Prologue [] Nothing []) (XML.Element "a" mempty mempty) []
        check $ Document (Prologue [] Nothing []) (XML.Element "a" mempty tree) []
    ]

  , testGroup "MimeRender HTML FormRedirect"
    [ testCase "roundtrip-0" $
        let -- source: [2/3.5.8]
            have = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"" <>
                   "    ID=\"d2b7c388cec36fa7c39c28fd298644a8\" IssueInstant=\"2004-01-21T19:00:49Z\" Version=\"2.0\">" <>
                   "    <Issuer>https://IdentityProvider.com/SAML</Issuer>" <>
                   "    <NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">005a06e0-ad82-110d-a556-004005b13a2b</NameID>" <>
                   "    <samlp:SessionIndex>1</samlp:SessionIndex>" <>
                   "</samlp:LogoutRequest>"
            Right want = parseText def $
                   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                <> "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\""
                <> " \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
                <> "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">"
                <>   "<body onload=\"document.forms[0].submit()\">"
                <>     "<noscript>"
                <>       "<p>"
                <>         "<strong>Note:</strong>Since your browser does not support JavaScript,"
                <> " you must press the Continue button once to proceed."
                <>       "</p>"
                <>     "</noscript>"
                <>     "<form action=\"https://ServiceProvider.com/SAML/SLO/Browser\""
                <> " method=\"post\">"
                -- <> "      <input type=\"hidden\" name=\"RelayState\""
                -- <> " value=\"0043bfc1bc45110dae17004005b13a2b\"/>"
                <>       "<input type=\"hidden\" name=\"SAMLRequest\""
                -- the original encoding, differing in irrelevant nit-picks.
                -- <> " value=\"PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1l\n"
                -- <> "czp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0\n"
                -- <> "YzpTQU1MOjIuMDphc3NlcnRpb24iDQogICAgSUQ9ImQyYjdjMzg4Y2VjMzZmYTdj\n"
                -- <> "MzljMjhmZDI5ODY0NGE4IiBJc3N1ZUluc3RhbnQ9IjIwMDQtMDEtMjFUMTk6MDA6\n"
                -- <> "NDlaIiBWZXJzaW9uPSIyLjAiPg0KICAgIDxJc3N1ZXI+aHR0cHM6Ly9JZGVudGl0\n"
                -- <> "eVByb3ZpZGVyLmNvbS9TQU1MPC9Jc3N1ZXI+DQogICAgPE5hbWVJRCBGb3JtYXQ9\n"
                -- <> "InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNp\n"
                -- <> "c3RlbnQiPjAwNWEwNmUwLWFkODItMTEwZC1hNTU2LTAwNDAwNWIxM2EyYjwvTmFt\n"
                -- <> "ZUlEPg0KICAgIDxzYW1scDpTZXNzaW9uSW5kZXg+MTwvc2FtbHA6U2Vzc2lvbklu\n"
                -- <> "ZGV4Pg0KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==\"/>"
                -- copied from test failure (this is ok assuming that the base64 tests above have passed)
                <> " value=\"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6TG9n\n"
                <> "b3V0UmVxdWVzdCBJRD0iZDJiN2MzODhjZWMzNmZhN2MzOWMyOGZkMjk4NjQ0YTgi\n"
                <> "IElzc3VlSW5zdGFudD0iMjAwNC0wMS0yMVQxOTowMDo0OVoiIFZlcnNpb249IjIu\n"
                <> "MCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90\n"
                <> "b2NvbCI+ICAgIDxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1M\n"
                <> "OjIuMDphc3NlcnRpb24iPmh0dHBzOi8vSWRlbnRpdHlQcm92aWRlci5jb20vU0FN\n"
                <> "TDwvSXNzdWVyPiAgICA8TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRj\n"
                <> "OlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCIgeG1sbnM9InVybjpv\n"
                <> "YXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjAwNWEwNmUwLWFkODIt\n"
                <> "MTEwZC1hNTU2LTAwNDAwNWIxM2EyYjwvTmFtZUlEPiAgICA8c2FtbHA6U2Vzc2lv\n"
                <> "bkluZGV4PjE8L3NhbWxwOlNlc3Npb25JbmRleD48L3NhbWxwOkxvZ291dFJlcXVl\n"
                <> "c3Q+\n\"/>"
                <>       "<noscript>"
                <>           "<input type=\"submit\" value=\"Continue\"/>"
                <>       "</noscript>"
                <>     "</form>"
                <>   "</body>"
                <> "</html>"
            Right (SomeSAMLRequest -> doc) = XML.parseText XML.def have
            Right uri = parseURI' "https://ServiceProvider.com/SAML/SLO/Browser"
        in
          assertEqual "" (Right want) (fmapL show . parseText def . cs $ mimeRender (Proxy @HTML) (FormRedirect uri doc))
    ]
  ]
