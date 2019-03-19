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
import Data.Maybe (maybeToList, fromJust)
import Data.String.Conversions
import Network.HTTP.Types.Status (statusCode)
import Network.Wai.Test
import SAML2.Util
import SAML2.WebSSO
import SAML2.WebSSO.Test.Credentials
import SAML2.WebSSO.Test.MockResponse
import Servant
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher
import Text.Show.Pretty (ppShow)
import Text.XML as XML
import URI.ByteString as URI
import URI.ByteString.QQ
import Util

import qualified Data.ByteString.Base64.Lazy as EL (encode, decodeLenient)
import qualified Data.Map as Map
import qualified Data.UUID as UUID
import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml


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

    it "works with proper %0a newlines" $ do
      let encoded = "MTIzN\nDUK\n"
      EL.decodeLenient encoded `shouldBe` "12345\n"

    it "works with MSDOS and %0d%0a newlines" $ do
      let encoded = "MTIzN\r\nDUK\r\n"
      EL.decodeLenient encoded `shouldBe` "12345\n"

    it "works with just plain broken input" $ do
      -- there is no strong reason why we would want this test to pass or fail; it is just here to
      -- document the current behavior.  see also the comment in 'parseAuthnResponseBody'.
      let encoded = "MTI##zN@@DUK??"
      EL.decodeLenient encoded `shouldBe` "12345\n"

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
              <>     "<form action=\"https://ServiceProvider.com/SAML/SLO/Browser/%25%25\""
              <> " method=\"post\">"
              <>       "<input type=\"hidden\" name=\"SAMLRequest\""
              <> " value=\"PHNhbWxwOkxvZ291dFJlcXVlc3QgSUQ9ImQyYjdjMzg4Y2VjMzZmYTdjMzljMjhmZDI5ODY0NGE4IiBJc3N1ZUluc3RhbnQ9IjIwMDQtMDEtMjFUMTk6MDA6NDlaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPiAgICA8SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL0lkZW50aXR5UHJvdmlkZXIuY29tL1NBTUw8L0lzc3Vlcj4gICAgPE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj4wMDVhMDZlMC1hZDgyLTExMGQtYTU1Ni0wMDQwMDViMTNhMmI8L05hbWVJRD4gICAgPHNhbWxwOlNlc3Npb25JbmRleD4xPC9zYW1scDpTZXNzaW9uSW5kZXg+PC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==\"/>"
              <>       "<noscript>"
              <>           "<input type=\"submit\" value=\"Continue\"/>"
              <>       "</noscript>"
              <>     "</form>"
              <>   "</body>"
              <> "</html>"
          Right (SomeSAMLRequest -> doc) = XML.parseText XML.def have
          spuri = [uri|https://ServiceProvider.com/SAML/SLO/Browser/%%|]

      Right want `shouldBe` (fmapL show . parseText def . cs $ mimeRender (Proxy @HTML) (FormRedirect spuri doc))

  describe "simpleVerifyAuthnResponse" $ do
    let check :: Bool -> Maybe Bool -> Bool -> Spec
        check goodsig mgoodkey expectOutcome =
          it (show expectOutcome) $ do
            let respfile = if goodsig
                  then "microsoft-authnresponse-2.xml"
                  else "microsoft-authnresponse-2-badsig.xml"

            resp :: LBS
              <- cs <$> readSampleIO respfile
            midpcfg :: Maybe IdPConfig_
              <- case mgoodkey of
                   Nothing -> pure Nothing
                   Just goodkey -> do
                     let cfgfile = if goodkey
                           then "microsoft-idp-config.yaml"
                           else "microsoft-idp-config-badkey.yaml"
                     either (error . show) (pure . Just)
                       =<< (Yaml.decodeEither' . cs <$> readSampleIO cfgfile)

            let run :: TestSP a -> IO a
                run action = do
                  ctx <- mkTestCtxSimple
                  modifyMVar_ ctx (pure . (ctxIdPs .~ maybeToList midpcfg))
                  ioFromTestSP ctx action

                missuer = (^. idpMetadata . edIssuer) <$> midpcfg

                go :: TestSP ()
                go = do
                  creds <- issuerToCreds missuer
                  simpleVerifyAuthnResponse creds resp

            if expectOutcome
              then run go `shouldReturn` ()
              else run go `shouldThrow` anyException

    context "good signature" $ do
      context "known key"    $ check True (Just True) True
      context "bad key"      $ check True (Just False) False
      context "unknown key"  $ check True Nothing False

    context "bad signature"  $ do
      context "known key"    $ check False (Just True) False
      context "bad key"      $ check False (Just False) False
      context "unknown key"  $ check False Nothing False

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

        testAuthRespApp :: IO CtxV -> SpecWith (CtxV, Application) -> Spec
        testAuthRespApp = withapp (Proxy @APIAuthResp')
          (authresp' defSPIssuer defResponseURI (HandleVerdictRedirect simpleOnSuccess))

    context "unknown idp" . testAuthRespApp mkTestCtxSimple $ do
      let errmsg = "Unknown IdP: Issuer"
      it "responds with 404" . runtest $ \ctx -> do
        postTestAuthnResp ctx False `shouldRespondWith`
          404

    context "known idp, bad timestamp" . testAuthRespApp mkTestCtxWithIdP $ do
      it "responds with 403" . runtest $ \ctx -> do
        postTestAuthnResp ctx True `shouldRespondWith`
          403 { matchBody = bodyContains "IssueInstant" }

    context "known idp, good timestamp" . testAuthRespApp mkTestCtxWithIdP $ do
      it "responds with 303" . runtest $ \ctx -> do
        postTestAuthnResp ctx False `shouldRespondWith`
          303 { matchBody = bodyContains "<body><p>SSO successful, redirecting to" }


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
            creds <- issuerToCreds (Just idpissuer)
            simpleVerifyAuthnResponse creds authnrespLBS
          result `shouldSatisfy` expectation

    it "Produces output that passes 'simpleVerifyAuthnResponse'" $ do
      check sampleIdPCert isRight

    it "Produces output that is rejected by 'simpleVerifyAuthnResponse' if the signature is wrong" $ do
      check sampleIdPCert2 isLeft


  describe "vendor compatibility tests" $ do
    let testAuthRespApp :: HasCallStack => URI.URI -> SpecWith (CtxV, Application) -> Spec
        testAuthRespApp ssoURI = withapp (Proxy @("sso" :> APIAuthResp'))
            (authresp' spissuer respuri (HandleVerdictRedirect simpleOnSuccess))
            mkTestCtxSimple
          where
            spissuer = Issuer <$> respuri
            respuri = pure ssoURI

        vendorCompatibility :: HasCallStack => FilePath -> URI.URI -> Spec
        vendorCompatibility filePath ssoURI = testAuthRespApp ssoURI $ do
          it filePath . runtest $ \ctx -> do
            authnrespRaw :: LT            <- readSampleIO ("vendors/" <> filePath <> "-authnresp.xml")
            authnresp    :: AuthnResponse <- either (error . show) pure $ decode authnrespRaw
            idpmeta      :: IdPMetadata   <- readSampleIO ("vendors/" <> filePath <> "-metadata.xml") >>=
                                             either (error . show) pure . decode

            let idpcfg = IdPConfig {..}
                  where
                    _idpId = IdPId UUID.nil
                    _idpMetadata = idpmeta
                    _idpExtraInfo = ()

                -- NB: the following two bits of info are taken from the unsigned AuthnResponse
                -- header.  the test still makes perfect sense given the information is available in
                -- the header.  if it is not, this is legitimate.  in that case, just dig into the
                -- assertions and take the information from there.

                -- authnresp inResponseTo, with comfortable end of life.
                reqstore :: Map.Map (ID AuthnRequest) Time
                reqstore = Map.singleton (fromJust $ authnresp ^. rspInRespTo) timeInALongTime

                -- 1 second after authnresp IssueInstant
                now :: Time
                now = addTime 1 $ authnresp ^. rspIssueInstant

            liftIO . modifyMVar_ ctx $ \ctx' -> pure $ ctx'
              & ctxIdPs .~ [idpcfg]
              -- & ctxConfig . cfgSPAppURI .~ _
              -- (the SPAppURI default is a incorrect, but that should not invalidate the test)
              & ctxConfig . cfgSPSsoURI .~ ssoURI
              & ctxRequestStore .~ reqstore
              & ctxNow .~ now

            -- it is essential to not use @encode authnresp@ here, as that has no signature!
            verdict :: SResponse <- postHtmlForm "/sso/authresp"
              [("SAMLResponse", cs . EL.encode . cs $ authnrespRaw)]

            when (statusCode (simpleStatus verdict) /= 303) . liftIO $ do
              putStrLn . ppShow . (verdict,) =<< readMVar ctx
            liftIO $ statusCode (simpleStatus verdict) `shouldBe` 303


    vendorCompatibility "okta.com" [uri|https://staging-nginz-https.zinfra.io/sso/finalize-login|]
    -- https://developer.okta.com/signup/

    vendorCompatibility "azure.microsoft.com" [uri|https://zb2.zerobuzz.net:60443/authresp|]
    -- https://azure.microsoft.com/en-us/

    vendorCompatibility "centrify.com" [uri|https://prod-nginz-https.wire.com/sso/finalize-login|]

    -- TODO:
    --  * onelogin
    --  * jives [https://community.jivesoftware.com/docs/DOC-240217#jive_content_id_IdP_Metadata]
