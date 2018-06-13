{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-orphans #-}

module Test.SAML2.WebSSO.APISpec (spec) where

import Control.Concurrent.MVar (newMVar)
import Control.Exception (throwIO, ErrorCall(ErrorCall))
import Data.Either
import Data.EitherR
import Data.String.Conversions
import Lens.Micro
import SAML2.WebSSO
import Servant
import Servant.Utils.Enter
import Shelly (shelly, run, setStdin, silently)
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher
import TestSP
import Text.XML as XML
import Text.XML.DSig
import Text.XML.Util
import URI.ByteString.QQ
import Util

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml


newtype SomeSAMLRequest = SomeSAMLRequest { fromSomeSAMLRequest :: XML.Document }
  deriving (Eq, Show)

instance HasFormRedirect SomeSAMLRequest where
  formRedirectFieldName _ = "SAMLRequest"

instance HasXML SomeSAMLRequest where
  nameSpaces Proxy = []
  parse = fmap SomeSAMLRequest . parse

instance HasXMLRoot SomeSAMLRequest where
  renderRoot (SomeSAMLRequest doc) = renderRoot doc

base64ours, base64theirs :: HasCallStack => SBS -> IO SBS
base64ours = pure . cs . EL.encode . cs
base64theirs sbs = shelly . silently $ cs <$> (setStdin (cs sbs) >> run "/usr/bin/base64" ["--wrap", "0"])


-- on servant-0.12 or later, use 'hoistServer':
-- <https://github.com/haskell-servant/servant/blob/master/servant/CHANGELOG.md#significant-changes-1>
withapp :: forall (api :: *).
  ( Enter (ServerT api TestSP) TestSP Handler (Server api)
  , HasServer api '[]
  ) => Proxy api -> ServerT api TestSP -> IO Ctx -> SpecWith Application -> Spec
withapp proxy handler mkctx = with (mkctx <&> \ctx -> serve proxy (enter (NT (nt @TestSP ctx)) handler :: Server api))


spec :: Spec
spec = describe "API" $ do
  describe "base64 encoding" $ do
    describe "compatible with /usr/bin/base64" $ do
      let check :: LBS -> Spec
          check input = it (show input) $ do
            o <- base64ours (cs input)
            t <- base64theirs (cs input)
            chomp o `shouldBe` chomp t

          chomp = reverse . dropWhile (== '\n') . reverse . cs

      check ""
      check "..."
      check "foiy0t019061.........|||"
      check (cs $ replicate 1000 '_')

  describe "MimeRender HTML FormRedirect" $ do
    it "roundtrip-0" $ do
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
              -- <> " value=\"PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1l"
              -- <> "czp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0"
              -- <> "YzpTQU1MOjIuMDphc3NlcnRpb24iDQogICAgSUQ9ImQyYjdjMzg4Y2VjMzZmYTdj"
              -- <> "MzljMjhmZDI5ODY0NGE4IiBJc3N1ZUluc3RhbnQ9IjIwMDQtMDEtMjFUMTk6MDA6"
              -- <> "NDlaIiBWZXJzaW9uPSIyLjAiPg0KICAgIDxJc3N1ZXI+aHR0cHM6Ly9JZGVudGl0"
              -- <> "eVByb3ZpZGVyLmNvbS9TQU1MPC9Jc3N1ZXI+DQogICAgPE5hbWVJRCBGb3JtYXQ9"
              -- <> "InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNp"
              -- <> "c3RlbnQiPjAwNWEwNmUwLWFkODItMTEwZC1hNTU2LTAwNDAwNWIxM2EyYjwvTmFt"
              -- <> "ZUlEPg0KICAgIDxzYW1scDpTZXNzaW9uSW5kZXg+MTwvc2FtbHA6U2Vzc2lvbklu"
              -- <> "ZGV4Pg0KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==\"/>"
              -- copied from test failure (this is ok assuming that the base64 tests above have passed)
              <> " value=\"PHNhbWxwOkxvZ291dFJlcXVlc3QgSUQ9ImQyYjdjMzg4Y2VjMzZmYTdjMzljMjhmZDI5ODY0NGE4IiBJc3N1ZUluc3RhbnQ9IjIwMDQtMDEtMjFUMTk6MDA6NDlaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPiAgICA8SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL0lkZW50aXR5UHJvdmlkZXIuY29tL1NBTUw8L0lzc3Vlcj4gICAgPE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj4wMDVhMDZlMC1hZDgyLTExMGQtYTU1Ni0wMDQwMDViMTNhMmI8L05hbWVJRD4gICAgPHNhbWxwOlNlc3Npb25JbmRleD4xPC9zYW1scDpTZXNzaW9uSW5kZXg+PC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==\"/>"
              <>       "<noscript>"
              <>           "<input type=\"submit\" value=\"Continue\"/>"
              <>       "</noscript>"
              <>     "</form>"
              <>   "</body>"
              <> "</html>"
          Right (SomeSAMLRequest -> doc) = XML.parseText XML.def have
          spuri = [uri|https://ServiceProvider.com/SAML/SLO/Browser|]

      Right want `shouldBe` (fmapL show . parseText def . cs $ mimeRender (Proxy @HTML) (FormRedirect spuri doc))

  describe "simpleVerifyAuthnResponse" $ do
    let check goodsig knownkey expectOutcome =
          it (show expectOutcome) $ do
            let respfile = if goodsig
                  then "microsoft-authnresponse-2.xml"
                  else "microsoft-authnresponse-2-badsig.xml"

            resp :: LBS <- cs <$> readSampleIO respfile
            Right (cert :: X509.SignedCertificate) <- parseKeyInfo <$> readSampleIO "microsoft-idp-keyinfo.xml"
            let Right (SignCreds _ (SignKeyRSA (key :: RSA.PublicKey))) = keyInfoToCreds cert

            let foundkey :: Issuer -> Either String RSA.PublicKey
                foundkey _ = if knownkey then Right key else Left "foundkey failed"

                go :: Either String ()
                go = simpleVerifyAuthnResponse (Just $ Issuer [uri|http://some_issuer/|]) foundkey resp

            if expectOutcome
              then go `shouldBe` Right ()
              else go `shouldSatisfy` isLeft

    context "good signature" $ do
      context "known key"    $ check True True True
      context "unknown key"  $ check True False False

    context "bad signature"  $ do
      context "known key"    $ check False True False
      context "unknown key"  $ check False False False

  describe "cookies" $ do
    let c1 = togglecookie Nothing
        c2 = togglecookie (Just "nick")
        rndtrip
          = headerValueToCookie
          . cs . snd
          . cookieToHeader

    it  "roundtrip-1" $ Left "missing cookie value" `shouldBe` rndtrip c1
    it  "roundtrip-2" $ Right c2 `shouldBe` rndtrip c2


  describe "meta" . withapp (Proxy @APIMeta') (meta "toy-sp" (Proxy @API) (Proxy @APIAuthResp')) mkTestCtx1 $ do
    it "responds with 200 and an 'SPSSODescriptor'" $ do
      get "/meta" `shouldRespondWith` 200 { matchBody = bodyContains "OrganizationName xml:lang=\"EN\">toy-sp" }

  describe "authreq" $ do
    context "unknown idp" . withapp (Proxy @APIAuthReq') authreq mkTestCtx1 $ do
      it "responds with 404" $ do
        get "/authreq/no-such-idp" `shouldRespondWith` 404

    context "known idp" . withapp (Proxy @APIAuthReq') authreq mkTestCtx2 $ do
      it "responds with 200" $ do
        get "/authreq/myidp" `shouldRespondWith` 200

      it "responds with a body that contains the IdPs response URL" $ do
        myidp <- liftIO mkmyidp
        get "/authreq/myidp" `shouldRespondWith` 200
          { matchBody = bodyContains . cs . renderURI $ myidp ^. idpRequestUri }

  describe "authresp" $ do
    let mkpostresp = readSampleIO "microsoft-authnresponse-2.xml"
          <&> \sample -> postHtmlForm "/authresp" [("SAMLResponse", cs . EL.encode . cs $ sample)]

    context "unknown idp" . withapp (Proxy @APIAuthResp') (authresp simpleOnSuccess) mkTestCtx1 $ do
      let errmsg = "invalid signature: unknown issuer: Issuer"
      it "responds with 400" $ do
        postresp <- liftIO mkpostresp
        postresp `shouldRespondWith` 400 { matchBody = bodyContains errmsg }

    context "known idp, bad timestamp" . withapp (Proxy @APIAuthResp') (authresp simpleOnSuccess) mkTestCtx2 $ do
      it "responds with 402" $ do
        postresp <- liftIO mkpostresp
        postresp `shouldRespondWith`
          403 { matchBody = bodyContains "violation of NotBefore condition" }

    let mkTestCtx3' = do
          reqstore <- newMVar $ Map.fromList [(ID "idcf2299ac551b42f1aa9b88804ed308c2", unsafeReadTime "2019-04-14T10:53:57Z")]
          mkTestCtx3
            <&> ctxNow .~ unsafeReadTime "2018-04-14T10:53:57Z"
            <&> ctxConfig . cfgSPAppURI .~ [uri|https://zb2.zerobuzz.net:60443/authresp|]
            <&> ctxRequestStore .~ reqstore
    context "known idp, good timestamp" . withapp (Proxy @APIAuthResp') (authresp simpleOnSuccess) mkTestCtx3' $ do
      it "responds with 302" $ do
        postresp <- liftIO mkpostresp
        postresp `shouldRespondWith` 302 { matchBody = bodyEquals "" }


  describe "idp smoke tests" $ do
    burnIdP "octa.yaml" "octa-resp-1.base64" "2018-05-25T10:57:16.135Z" "https://zb2.zerobuzz.net:60443/"
    burnIdP "microsoft-idp-config.yaml" "microsoft-authnresponse-2.base64" "2018-04-14T10:53:57Z" "https://zb2.zerobuzz.net:60443/authresp"
    -- TODO: centrify


burnIdP :: FilePath -> FilePath -> ST -> ST -> Spec
burnIdP cfgPath respXmlPath (cs -> currentTime) audienceURI = do
  let ctx :: IO Ctx
      ctx = do
        testCtx1 <- mkTestCtx1
        reqstore <- newMVar $ Map.fromList
          -- it would be probably better to also take this ID (and timeout?) as an argument(s).
          [ (ID "idcf2299ac551b42f1aa9b88804ed308c2", unsafeReadTime "2019-04-14T10:53:57Z")
          , (ID "idafecfcff5cc64345b6ddde7ee47b4838", unsafeReadTime "2019-04-14T10:53:57Z")
          ]
        getIdP <&> \idp -> testCtx1 & ctxConfig . cfgIdps .~ [idp]
                                    & ctxNow .~ unsafeReadTime currentTime
                                    & ctxConfig . cfgSPAppURI .~ unsafeParseURI audienceURI
                                    & ctxRequestStore .~ reqstore

      getIdP :: IO IdPConfig_
      getIdP = either (throwIO . ErrorCall . show) pure =<< (Yaml.decodeEither . cs <$> readSampleIO cfgPath)

  describe ("smoke tests: " <> show cfgPath) $ do
    describe "authreq" . withapp (Proxy @APIAuthReq') authreq ctx $ do
      it "responds with 200" $ do
        idp <- liftIO getIdP
        get ("/authreq/" <> cs (idp ^. idpPath))
          `shouldRespondWith` 200 { matchBody = bodyContains "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" }

    describe "authresp" . withapp (Proxy @APIAuthResp') (authresp simpleOnSuccess) ctx $ do
      it "responds with 302" $ do
        sample <- liftIO $ cs <$> readSampleIO respXmlPath
        let postresp = postHtmlForm "/authresp" body
            body = [("SAMLResponse", sample)]
        postresp
          `shouldRespondWith` 302 { matchBody = bodyEquals "" }
