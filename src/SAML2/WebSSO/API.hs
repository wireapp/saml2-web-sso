{-# LANGUAGE OverloadedStrings #-}

-- | This is a partial implementation of Web SSO using the HTTP Post Binding [2/3.5].
--
-- The default API offers 3 end-points: one for retrieving the 'AuthnRequest' in a redirect to the
-- IdP; one for delivering the 'AuthnResponse' that will re-direct to some fixed landing page; and
-- one for retrieving the SP's metadata.
--
-- There are other scenarios, e.g. all resources on the page could be guarded with an authentication
-- check and redirect the client to the IdP, and make sure that the client lands on the initally
-- requested resource after successful authentication.  With the building blocks provided by this
-- module, it should be straight-forward to implemented all of these scenarios.
--
-- This module works best if imported qualified.
--
-- FUTUREWORK: servant-server is quite heavy.  we should have a cabal flag to exclude it.
module SAML2.WebSSO.API
  ( module SAML2.WebSSO.API
  , module SAML2.WebSSO.Servant
  ) where

import Control.Lens hiding (element)
import Control.Monad.Except hiding (ap)
import Data.EitherR
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe (catMaybes)
import Data.Proxy
import Data.String.Conversions
import Data.Time
import GHC.Generics
import SAML2.Util
import SAML2.WebSSO.Servant
import SAML2.WebSSO.Config
import SAML2.WebSSO.Error as SamlErr
import SAML2.WebSSO.SP
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Servant.API as Servant hiding (URI(..))
import Servant.Multipart
import Servant.Server
import Text.Hamlet.XML
import Text.Show.Pretty (ppShow)
import Text.XML
import Text.XML.Cursor
import Text.XML.DSig
import URI.ByteString

import qualified Data.ByteString.Base64.Lazy as EL (encode, decodeLenient)
import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified SAML2.WebSSO.Cookie as Cky


----------------------------------------------------------------------
-- saml web-sso api

type APIMeta     = Get '[XML] SPMetadata
type APIAuthReq  = Capture "idp" IdPId :> Get '[HTML] (FormRedirect AuthnRequest)
type APIAuthResp = MultipartForm Mem AuthnResponseBody :> PostRedir '[HTML] (WithCookieAndLocation ST)

type APIMeta'     = "meta" :> APIMeta
type APIAuthReq'  = "authreq" :> APIAuthReq
type APIAuthResp' = "authresp" :> APIAuthResp

-- | Consider rate-limiting these end-points to mitigate DOS attacks.  'APIAuthReq' uses database
-- space, and 'APIAuthResp' uses both database space and CPU.
type API = APIMeta'
      :<|> APIAuthReq'
      :<|> APIAuthResp'

api :: forall err m. SPHandler (Error err) m => ST -> HandleVerdict m -> ServerT API m
api appName handleVerdict =
       meta appName defSPIssuer defResponseURI
  :<|> authreq' defSPIssuer
  :<|> authresp' defSPIssuer defResponseURI handleVerdict

-- | The 'Issuer' is an identifier of a SAML participant.  In this case, it's the SP, ie., ourselves.
defSPIssuer :: HasConfig m => m Issuer
defSPIssuer = Issuer <$> defResponseURI

-- | The URI that 'AuthnResponse' values are delivered to ('APIAuthResp').
defResponseURI :: HasConfig m => m URI
defResponseURI = getSsoURI (Proxy @API) (Proxy @APIAuthResp')


----------------------------------------------------------------------
-- authentication response body processing

-- | An 'AuthnResponseBody' contains a 'AuthnResponse', but you need to give it a trust base forn
-- signature verification first, and you may get an error when you're looking at it.
newtype AuthnResponseBody = AuthnResponseBody
  { fromAuthnResponseBody :: forall m err. SPStoreIdP (Error err) m => m AuthnResponse }

renderAuthnResponseBody :: AuthnResponse -> LBS
renderAuthnResponseBody = EL.encode . cs . encode

-- | Implies verification, hence the constraint.
parseAuthnResponseBody :: forall m err. SPStoreIdP (Error err) m => LBS -> m AuthnResponse
parseAuthnResponseBody base64 = do
  -- https://www.ietf.org/rfc/rfc4648.txt states that all "noise" characters should be rejected
  -- unless another standard says they should be ignored.  'EL.decodeLenient' chooses the radical
  -- approach and ignores all "noise" characters.  since we have to deal with at least %0a, %0d%0a,
  -- '=', and probably other noise, this seems the safe thing to do.  It is no less secure than
  -- rejecting some noise characters and ignoring others.
  let xmltxt = EL.decodeLenient base64
  resp <-
    either (throwError . BadSamlResponseXmlError . cs) pure $
    decode (cs xmltxt)
  creds <- issuerToCreds (resp ^. rspIssuer)
  simpleVerifyAuthnResponse creds xmltxt
  pure resp

authnResponseBodyToMultipart :: AuthnResponse -> MultipartData tag
authnResponseBodyToMultipart resp = MultipartData [Input "SAMLResponse" (cs $ renderAuthnResponseBody resp)] []

instance FromMultipart Mem AuthnResponseBody where
  fromMultipart resp = Just (AuthnResponseBody eval)
    where
      eval :: forall m err. SPStoreIdP (Error err) m => m AuthnResponse
      eval = do
        base64 <- maybe (throwError BadSamlResponseFormFieldMissing) pure $
                  lookupInput "SAMLResponse" resp
        parseAuthnResponseBody (cs base64)

issuerToCreds :: forall m err. SPStoreIdP (Error err) m => Maybe Issuer -> m (NonEmpty SignCreds)
issuerToCreds Nothing = throwError BadSamlResponseIssuerMissing
issuerToCreds (Just issuer) = do
    certs <- (^. idpMetadata . edCertAuthnResponse) <$> getIdPConfigByIssuer issuer
    let err = throwError . InvalidCert . ((encodeElem issuer <> ": ") <>) . cs
    forM certs $ either err pure . certToCreds

-- | Pull assertions sub-forest and pass unparsed xml input to 'verify' with a reference to
-- each assertion individually.  The input must be a valid 'AuthnResponse'.  All assertions
-- need to be signed by the issuer given in the arguments using the same key.
simpleVerifyAuthnResponse :: forall m err. MonadError (Error err) m => NonEmpty SignCreds -> LBS -> m ()
simpleVerifyAuthnResponse creds raw = do
    doc :: Cursor <- do
      let err = throwError . BadSamlResponseSamlError . cs . show
      either err (pure . fromDocument) (parseLBS def raw)

    assertions :: [Element] <- do
      let elemOnly (NodeElement el) = Just el
          elemOnly _ = Nothing
      case catMaybes $ elemOnly . node <$>
             (doc $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion") of
        [] -> throwError BadSamlResponseNoAssertions
        some@(_:_) -> pure some

    nodeids :: [String] <- do
      let assertionID :: Element -> m String
          assertionID (Element _ attrs _)
            = maybe (throwError BadSamlResponseAssertionWithoutID) (pure . cs)
            $ Map.lookup "ID" attrs
      assertionID `mapM` assertions

    do
      let err = throwError . BadSamlResponseInvalidSignature . cs
      either err pure $ verify creds raw `mapM_` nodeids


----------------------------------------------------------------------
-- form redirect

-- | [2/3.5.4]
data FormRedirect xml = FormRedirect URI xml
  deriving (Eq, Show, Generic)

class HasXML xml => HasFormRedirect xml where
  formRedirectFieldName :: xml -> ST

instance HasFormRedirect AuthnRequest where
  formRedirectFieldName _ = "SAMLRequest"

instance HasXMLRoot xml => MimeRender HTML (FormRedirect xml) where
  mimeRender (Proxy :: Proxy HTML)
             (FormRedirect (cs . serializeURIRef' -> uri) (cs . EL.encode . cs . encode -> value))
    = mkHtml [xml|
                 <body onload="document.forms[0].submit()">
                   <noscript>
                     <p>
                       <strong>
                         Note:
                       Since your browser does not support JavaScript, you must press the Continue button once to proceed.
                   <form action=#{uri} method="post">
                     <input type="hidden" name="SAMLRequest" value=#{value}>
                     <noscript>
                       <input type="submit" value="Continue">
             |]

instance HasXMLRoot xml => Servant.MimeUnrender HTML (FormRedirect xml) where
  mimeUnrender Proxy lbs = do
    cursor <- fmapL show $ fromDocument <$> parseLBS def lbs
    let formAction :: [ST] = cursor $// element "{http://www.w3.org/1999/xhtml}form" >=> attribute "action"
        formBody   :: [ST] = cursor $// element "{http://www.w3.org/1999/xhtml}input" >=> attributeIs "name" "SAMLRequest" >=> attribute "value"
    uri  <- fmapL (<> (": " <> show formAction)) . parseURI' $ mconcat formAction
    resp <- fmapL (<> (": " <> show formBody)) . decode . cs . EL.decodeLenient . cs $ mconcat formBody
    pure $ FormRedirect uri resp


----------------------------------------------------------------------
-- handlers

meta
  :: forall m err. (SPHandler (Error err) m, HasConfig m)
  => ST -> m Issuer -> m URI -> m SPMetadata
meta appName getRequestIssuer getResponseURI = do
  enterH "meta"
  Issuer org <- getRequestIssuer
  resp       <- getResponseURI
  contacts   <- (^. cfgContacts) <$> getConfig
  mkSPMetadata appName org resp contacts

-- | Create authnreq, store it for comparison against assertions later, and return it in an HTTP
-- redirect together with the IdP's URI.
authreq
  :: (SPHandler (Error err) m)
  => NominalDiffTime -> m Issuer
  -> IdPId -> m (FormRedirect AuthnRequest)
authreq lifeExpectancySecs getIssuer idpid = do
  enterH "authreq"
  uri <- (^. idpMetadata . edRequestURI) <$> getIdPConfig idpid
  logger Debug $ "authreq uri: " <> cs (renderURI uri)
  req <- createAuthnRequest lifeExpectancySecs getIssuer
  logger Debug $ "authreq req: " <> cs (encode req)
  leaveH $ FormRedirect uri req

-- | 'authreq' with request life expectancy defaulting to 8 hours.
authreq'
  :: (SPHandler (Error err) m)
  => m Issuer
  -> IdPId -> m (FormRedirect AuthnRequest)
authreq' = authreq defReqTTL

defReqTTL :: NominalDiffTime
defReqTTL = 15 * 60  -- seconds

-- | parse and validate response, and pass the verdict to a user-provided verdict handler.  the
-- handler takes a response and a verdict (provided by this package), and can cause any effects in
-- 'm' and return anything it likes.
authresp
  :: SPHandler (Error err) m
  => m Issuer -> m URI -> (AuthnResponse -> AccessVerdict -> m resp)
  -> AuthnResponseBody -> m resp
authresp getSPIssuer getResponseURI handleVerdictAction body = do
  enterH "authresp: entering"
  jctx :: JudgeCtx      <- JudgeCtx <$> getSPIssuer <*> getResponseURI
  resp :: AuthnResponse <- fromAuthnResponseBody body
  logger Debug $ "authresp: " <> ppShow resp
  verdict <- judge resp jctx
  logger Debug $ "authresp: " <> show verdict
  handleVerdictAction resp verdict

-- | a variant of 'authresp' with a less general verdict handler.
authresp'
  :: SPHandler (Error err) m
  => m Issuer -> m URI -> HandleVerdict m
  -> AuthnResponseBody -> m (WithCookieAndLocation ST)
authresp' getRequestIssuerURI getResponseURI handleVerdict body = do
  let handleVerdictAction resp verdict = case handleVerdict of
        HandleVerdictRedirect onsuccess -> simpleHandleVerdict onsuccess verdict
        HandleVerdictRaw action -> throwError . CustomServant =<< action resp verdict
  authresp getRequestIssuerURI getResponseURI handleVerdictAction body


type OnSuccessRedirect m = UserRef -> m (Cky, URI)

type WithCookieAndLocation = Headers '[Servant.Header "Set-Cookie" Cky, Servant.Header "Location" URI]
type Cky = Cky.SimpleSetCookie CookieName
type CookieName = "saml2-web-sso"

simpleOnSuccess :: SPHandler (Error err) m => OnSuccessRedirect m
simpleOnSuccess uid = do
  cky    <- Cky.toggleCookie "/" $ Just (userRefToST uid, defReqTTL)
  appuri <- (^. cfgSPAppURI) <$> getConfig
  pure (cky, appuri)

-- | We support two cases: redirect with a cookie, and a generic response with arbitrary status,
-- headers, and body.  The latter case fits the 'ServantErr' type well, but we give it a more
-- suitable name here.
data HandleVerdict m
  = HandleVerdictRedirect (OnSuccessRedirect m)
  | HandleVerdictRaw (AuthnResponse -> AccessVerdict -> m ResponseVerdict)

type ResponseVerdict = ServantErr

simpleHandleVerdict :: (SP m, SPHandler (Error err) m) => OnSuccessRedirect m -> AccessVerdict -> m (WithCookieAndLocation ST)
simpleHandleVerdict onsuccess = \case
    AccessDenied reasons
      -> logger Debug (show reasons) >> (throwError . Forbidden . cs $ ST.intercalate "; " (explainDeniedReason <$> reasons))
    AccessGranted uid
      -> onsuccess uid <&> \(setcookie, uri)
                             -> addHeader setcookie $ addHeader uri ("SSO successful, redirecting to " <> renderURI uri)


----------------------------------------------------------------------
-- handler combinators

-- | Write error info to log, and apologise to client.
crash :: (SP m, MonadError (Error err) m) => String -> m a
crash msg = logger Fatal msg >> throwError UnknownError

enterH :: SP m => String -> m ()
enterH msg =
  logger Debug $ "entering handler: " <> msg

leaveH :: (Show a, SP m) => a -> m a
leaveH x = do
  logger Debug $ "leaving handler: " <> show x
  pure x
