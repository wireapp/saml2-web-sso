{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-orphans #-}

module Test.SAML2.WebSSO.APISpec (spec) where

import Control.Concurrent.MVar
import Control.Exception (SomeException, try)
import Control.Lens
import Control.Monad.Except
import Data.Either
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.String.Conversions
import Network.Wai.Test
import SAML2.Util
import SAML2.WebSSO
import SAML2.WebSSO.Test.Arbitrary (genFormRedirect, genAuthnRequest)
import SAML2.WebSSO.Test.Credentials
import SAML2.WebSSO.Test.MockResponse
import Servant
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher
import Text.XML as XML
import URI.ByteString.QQ
import Util

import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml
import qualified Hedgehog


hedgehogTests :: Hedgehog.Group
hedgehogTests = Hedgehog.Group "hedgehog tests" $
  [ ( "roundtrip: MimeRender HTML FormRedirect"
    , Hedgehog.property $ Hedgehog.forAll (genFormRedirect genAuthnRequest) >>=
        \formRedirect -> Hedgehog.tripping formRedirect (mimeRender (Proxy @HTML)) (mimeUnrender (Proxy @HTML))
    )
  ]


burnIdP :: FilePath -> FilePath -> ST -> ST -> Spec
burnIdP cfgPath respXmlPath (cs -> currentTime) audienceURI = do
  let mkctx :: IO CtxV
      mkctx = do
        testCtx1 <- mkTestCtxSimple
        let reqstore = Map.fromList
              -- it would be probably better to also take this ID (and timeout?) as an argument(s).
              [ (ID "idcf2299ac551b42f1aa9b88804ed308c2", unsafeReadTime "2019-04-14T10:53:57Z")
              , (ID "idafecfcff5cc64345b6ddde7ee47b4838", unsafeReadTime "2019-04-14T10:53:57Z")
              ]
        idp <- getIdP
        modifyMVar_ testCtx1 $ pure .
          ( (ctxIdPs .~ [idp])
          . (ctxNow .~ unsafeReadTime currentTime)
          . (ctxConfig . cfgSPAppURI .~ unsafeParseURI audienceURI)
          . (ctxRequestStore .~ reqstore)
          )
        pure testCtx1

      getIdP :: IO IdPConfig_
      getIdP = Yaml.decodeThrow . cs =<< readSampleIO cfgPath

  describe ("smoke tests: " <> show cfgPath) $ do
    describe "authreq" . withapp (Proxy @APIAuthReq') (authreq' defSPIssuer) mkctx $ do
      it "responds with 200" . runtest' $ do
        idp <- liftIO getIdP
        get ("/authreq/" <> cs (idPIdToST (idp ^. idpId)))
          `shouldRespondWith` 200 { matchBody = bodyContains "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" }

    describe "authresp" . testAuthRespApp mkctx $ do
      it "responds with 303" . runtest' $ do
        sample <- liftIO $ cs <$> readSampleIO respXmlPath
        let postresp = postHtmlForm "/authresp" body
            body = [("SAMLResponse", sample)]
        postresp
          `shouldRespondWith` 303


----------------------------------------------------------------------
-- test cases

spec :: Spec
spec = describe "API" $ do
  hedgehog $ Hedgehog.checkParallel hedgehogTests

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
    it "fake roundtrip-0" $ do
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

            resp :: LBS
              <- cs <$> readSampleIO respfile
            idpcfg :: IdPConfig_
              <- either (error . show) pure
                   =<< (Yaml.decodeEither' . cs <$> readSampleIO "microsoft-idp-config.yaml")

            let run :: TestSP a -> IO a
                run action = do
                  ctx <- mkTestCtxSimple
                  when knownkey $
                    modifyMVar_ ctx (pure . (ctxIdPs .~ [idpcfg | knownkey]))
                  ioFromTestSP ctx action

                issuer = idpcfg ^. idpMetadata . edIssuer

                go :: TestSP ()
                go = simpleVerifyAuthnResponse (Just issuer) resp

            if expectOutcome
              then run go `shouldReturn` ()
              else run go `shouldThrow` anyException

    context "good signature" $ do
      context "known key"    $ check True True True
      context "unknown key"  $ check True False False

    context "bad signature"  $ do
      context "known key"    $ check False True False
      context "unknown key"  $ check False False False

  describe "cookies" $ do
    let rndtrip
          = parseUrlPiece @Cky
          . cs . snd
          . cookieToHeader

    it  "roundtrip-1" $ do
      ctx <- mkTestCtxSimple
      c1 <- ioFromTestSP ctx $ toggleCookie @CookieName "/" Nothing
      rndtrip c1 `shouldBe` Left "missing cookie value"

    it  "roundtrip-2" $ do
      ctx <- mkTestCtxSimple
      c2 <- ioFromTestSP ctx $ toggleCookie @CookieName "/" (Just ("nick", defReqTTL))
      rndtrip c2 `shouldBe` Right c2


  describe "meta" . withapp (Proxy @APIMeta') (meta "toy-sp" defSPIssuer defResponseURI) mkTestCtxSimple $ do
    it "responds with 200 and an 'SPSSODescriptor'" . runtest' $ do
      get "/meta"
        `shouldRespondWith` 200 { matchBody = bodyContains "OrganizationName xml:lang=\"EN\">toy-sp" }


  describe "authreq" $ do
    context "invalid uuid" . withapp (Proxy @APIAuthReq') (authreq' defSPIssuer) mkTestCtxSimple $ do
      it "responds with 400" . runtest' $ do
        get "/authreq/broken-uuid" `shouldRespondWith` 400

    context "unknown idp" . withapp (Proxy @APIAuthReq') (authreq' defSPIssuer) mkTestCtxSimple $ do
      it "responds with 404" . runtest' $ do
        get "/authreq/6bf0dfb0-754f-11e8-b71d-00163e5e6c14" `shouldRespondWith` 404

    context "known idp" . withapp (Proxy @APIAuthReq') (authreq' defSPIssuer) mkTestCtxWithIdP $ do
      it "responds with 200" . runtest' $ do
        let idpid = testIdPConfig ^. idpId . to (cs . idPIdToST)
        get ("/authreq/" <> idpid) `shouldRespondWith` 200

      it "responds with a body that contains the IdPs response URL" . runtest' $ do
        let idpid = testIdPConfig ^. idpId . to (cs . idPIdToST)
        get ("/authreq/" <> idpid) `shouldRespondWith` 200
          { matchBody = bodyContains . cs . renderURI $ testIdPConfig ^. idpMetadata . edRequestURI }


  describe "authresp" $ do
    let -- Create an AuthnRequest in the SP, then call 'mkAuthnResponse' to make an 'AuthnResponse'
        -- in the IdP, then post the 'AuthnResponse' to the appropriate SP end-point.  @spmeta@ is
        -- needed for making the 'AuthnResponse'.
        postTestAuthnResp :: HasCallStack => CtxV -> Bool -> WaiSession SResponse
        postTestAuthnResp ctx badTimeStamp = do
          aresp <- liftIO . ioFromTestSP ctx $ do
            spmeta   :: SPMetadata     <- mkTestSPMetadata
            authnreq :: AuthnRequest   <- createAuthnRequest 3600 defSPIssuer
            SignedAuthnResponse aresp_
              <- (if badTimeStamp then timeTravel 1800 else id) $
                 mkAuthnResponse sampleIdPPrivkey testIdPConfig spmeta authnreq True
            pure aresp_
          postHtmlForm "/authresp" [("SAMLResponse", cs . EL.encode . renderLBS def $ aresp)]

    context "unknown idp" . testAuthRespApp mkTestCtxSimple $ do
      let errmsg = "Unknown IdP: Issuer"
      it "responds with 404" . runtest $ \ctx -> do
        postTestAuthnResp ctx False `shouldRespondWith`
          404

    context "known idp, bad timestamp" . testAuthRespApp mkTestCtxWithIdP $ do
      it "responds with 402" . runtest $ \ctx -> do
        postTestAuthnResp ctx True `shouldRespondWith`
          403 { matchBody = bodyContains "violation of NotBefore condition" }

    context "known idp, good timestamp" . testAuthRespApp mkTestCtxWithIdP $ do
      it "responds with 303" . runtest $ \ctx -> do
        postTestAuthnResp ctx False `shouldRespondWith`
          303 { matchBody = bodyContains "<body><p>SSO successful, redirecting to" }


  xdescribe "idp smoke tests" $ do
    burnIdP "okta-config.yaml" "okta-resp-1.base64" "2018-05-25T10:57:16.135Z" "https://zb2.zerobuzz.net:60443/"
    burnIdP "microsoft-idp-config.yaml" "microsoft-authnresponse-2.base64" "2018-04-14T10:53:57Z" "https://zb2.zerobuzz.net:60443/authresp"
    -- TODO: centrify
    -- TODO: onelogin


  describe "mkAuthnResponse (this is testing the test helpers)" $ do
    it "Produces output that decodes into 'AuthnResponse'" $ do
      ctx <- mkTestCtxWithIdP
      spmeta <- ioFromTestSP ctx mkTestSPMetadata
      Right authnreq :: Either SomeException AuthnRequest
        <- try . ioFromTestSP ctx $ createAuthnRequest 3600 defSPIssuer
      SignedAuthnResponse authnrespDoc
        <- ioFromTestSP ctx $ mkAuthnResponse sampleIdPPrivkey testIdPConfig spmeta authnreq True
      parseFromDocument @AuthnResponse authnrespDoc `shouldSatisfy` isRight

    let check :: X509.SignedCertificate -> (Either SomeException () -> Bool) -> IO ()
        check cert expectation = do
          let idpcfg = testIdPConfig & idpMetadata . edCertAuthnResponse .~ (cert :| [])
          ctx <- mkTestCtxSimple
          modifyMVar_ ctx $ pure . (ctxIdPs .~ [idpcfg])
          spmeta <- ioFromTestSP ctx mkTestSPMetadata
          let idpissuer :: Issuer        = idpcfg ^. idpMetadata . edIssuer
              spissuer  :: TestSP Issuer = defSPIssuer
          result :: Either SomeException () <- try . ioFromTestSP ctx $ do
            authnreq  <- createAuthnRequest 3600 spissuer
            SignedAuthnResponse authnrespDoc
              <- liftIO . ioFromTestSP ctx $ mkAuthnResponse sampleIdPPrivkey idpcfg spmeta authnreq True
            let authnrespLBS = renderLBS def authnrespDoc
            simpleVerifyAuthnResponse (Just idpissuer) authnrespLBS
          result `shouldSatisfy` expectation

    it "Produces output that passes 'simpleVerifyAuthnResponse'" $ do
      check sampleIdPCert isRight

    it "Produces output that is rejected by 'simpleVerifyAuthnResponse' if the signature is wrong" $ do
      check sampleIdPCert2 isLeft
