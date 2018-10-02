{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}

{-# OPTIONS_GHC -Wno-orphans #-}

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
module SAML2.WebSSO.API where

import Control.Monad.Except hiding (ap)
import Data.EitherR
import Data.Function
import Data.List
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe (catMaybes)
import Data.Proxy
import Data.String.Conversions
import Data.Time
import GHC.Generics
import Lens.Micro
import Network.HTTP.Media ((//))
import Network.HTTP.Types
import Network.Wai hiding (Response)
import Network.Wai.Internal as Wai
import SAML2.Util
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

import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Network.HTTP.Types.Header as HttpTypes
import qualified SAML2.WebSSO.Cookie as Cky
import qualified SAML2.WebSSO.XML.Meta as Meta


----------------------------------------------------------------------
-- saml web-sso api


type APIMeta     = Capture "idp" IdPId :> Get '[XML] SPMetadata
type APIAuthReq  = Capture "idp" IdPId :> Get '[HTML] (FormRedirect AuthnRequest)
type APIAuthResp = Capture "idp" IdPId :> MultipartForm Mem AuthnResponseBody :> PostRedir '[HTML] (WithCookieAndLocation ST)

type APIMeta'     = "meta" :> APIMeta
type APIAuthReq'  = "authreq" :> APIAuthReq
type APIAuthResp' = "authresp" :> APIAuthResp

type API = APIMeta'
      :<|> APIAuthReq'
      :<|> APIAuthResp'

api :: forall err m. SPHandler (Error err) m => ST -> HandleVerdict m -> ServerT API m
api appName handleVerdict =
       meta appName defRequestIssuer defResponseURI
  :<|> authreq' defRequestIssuer
  :<|> authresp' defRequestIssuer defResponseURI handleVerdict

defRequestIssuer :: HasConfig m => IdPId -> m Issuer
defRequestIssuer = fmap Issuer <$> getSsoURI' (Proxy @API) (Proxy @APIAuthReq')

defResponseURI :: HasConfig m => IdPId -> m URI
defResponseURI = getSsoURI' (Proxy @API) (Proxy @APIAuthResp')


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
  xmltxt <-
    either (throwError . BadSamlResponse . ("invalid base64 encoding: " <>) . cs) pure $
    EL.decode base64
  resp <-
    either (throwError . BadSamlResponse . cs) pure $
    decode (cs xmltxt)
  simpleVerifyAuthnResponse (resp ^. rspIssuer) xmltxt
  pure resp


-- | Pull assertions sub-forest and pass all trees in it to 'verify' individually.  The 'LBS'
-- argument must be a valid 'AuthnResponse'.  All assertions need to be signed by the issuer
-- given in the arguments using the same key.
simpleVerifyAuthnResponse :: forall m err. SPStoreIdP (Error err) m => Maybe Issuer -> LBS -> m ()
simpleVerifyAuthnResponse Nothing _ = throwError $ BadSamlResponse "missing issuer"
simpleVerifyAuthnResponse (Just issuer) raw = do
    creds :: NonEmpty SignCreds <- do
      certs <- (^. idpMetadata . edCertAuthnResponse) <$> getIdPConfigByIssuer issuer
      forM certs $ \cert -> certToCreds cert &
        either (throwError . BadServerConfig . ((encodeElem issuer <> ": ") <>) . cs) pure

    doc :: Cursor <- either (throwError . BadSamlResponse . ("could not parse document: " <>) . cs . show)
                            (pure . fromDocument)
                            (parseLBS def raw)

    let elemOnly (NodeElement el) = Just el
        elemOnly _ = Nothing

        assertions :: [Element]
        assertions = catMaybes $ elemOnly . node <$>
                     (doc $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    when (null assertions) $
      throwError . BadSamlResponse $ "no assertions: " <> cs (show raw)

    let assertionID :: Element -> m String
        assertionID el@(Element _ attrs _)
          = maybe (throwError . BadSamlResponse $ "assertion without ID: " <> cs (show el)) (pure . cs)
          $ Map.lookup "ID" attrs
    nodeids :: [String]
      <- assertionID `mapM` assertions

    either (throwError . BadSamlResponse . cs) pure $ (verify creds raw `mapM_` nodeids)


----------------------------------------------------------------------
-- servant, wai plumbing

-- TODO: move this section to module "SAML2.WebSSO.API.ServantPlumbing"?

type GetRedir = Verb 'GET 307
type PostRedir = Verb 'POST 303


-- | There is a tiny package `servant-xml`, which does essentially what this type and its
-- 'Mime{,Un}Render' instances do, but inlining this package seems easier.
data XML

instance Accept XML where
  contentType Proxy = "application" // "xml"

instance {-# OVERLAPPABLE #-} HasXMLRoot a => MimeRender XML a where
  mimeRender Proxy = cs . encode

instance {-# OVERLAPPABLE #-} HasXMLRoot a => MimeUnrender XML a where
  mimeUnrender Proxy = fmapL show . decode . cs


data HTML

instance  Accept HTML where
  contentType Proxy = "text" // "html"

instance MimeRender HTML ST where
  mimeRender Proxy msg = mkHtml
    [xml|
      <body>
        <p>
          #{msg}
    |]

authnResponseBodyToMultipart :: AuthnResponse -> MultipartData tag
authnResponseBodyToMultipart resp = MultipartData [Input "SAMLResponse" (cs $ renderAuthnResponseBody resp)] []

instance FromMultipart Mem AuthnResponseBody where
  fromMultipart resp = Just (AuthnResponseBody eval)
    where
      eval :: forall m err. SPStoreIdP (Error err) m => m AuthnResponse
      eval = do
        base64 <- maybe (throwError . BadSamlResponse $ "no SAMLResponse in the body") pure $
                  lookupInput "SAMLResponse" resp
        parseAuthnResponseBody (cs base64)


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
    resp <- fmapL (<> (": " <> show formBody)) $ decode . cs =<< (EL.decode . cs $ mconcat formBody)
    pure $ FormRedirect uri resp

mkHtml :: [Node] -> LBS
mkHtml nodes = renderLBS def doc
  where
    doc      = Document (Prologue [] (Just doctyp) []) root []
    doctyp   = Doctype "html" (Just $ PublicID "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd")
    root     = Element "html" rootattr nodes
    rootattr = Map.fromList [("xmlns", "http://www.w3.org/1999/xhtml"), ("xml:lang", "en")]


type WithCookieAndLocation = Headers '[Servant.Header "Set-Cookie" Cky, Servant.Header "Location" URI]

instance ToHttpApiData URI where
  toUrlPiece = renderURI


-- | [3.5.5.1] Caching
setHttpCachePolicy :: Middleware
setHttpCachePolicy ap rq respond = ap rq $ respond . addHeadersToResponse httpCachePolicy
  where
    httpCachePolicy :: HttpTypes.ResponseHeaders
    httpCachePolicy = [("Cache-Control", "no-cache, no-store"), ("Pragma", "no-cache")]

    addHeadersToResponse :: HttpTypes.ResponseHeaders -> Wai.Response -> Wai.Response
    addHeadersToResponse extraHeaders resp = case resp of
      ResponseFile status hdrs filepath part -> ResponseFile status (updH hdrs) filepath part
      ResponseBuilder status hdrs builder    -> ResponseBuilder status (updH hdrs) builder
      ResponseStream status hdrs body        -> ResponseStream status (updH hdrs) body
      ResponseRaw action resp'               -> ResponseRaw action $
                                                    addHeadersToResponse extraHeaders resp'
      where
        updH hdrs = nubBy ((==) `on` fst) $ extraHeaders ++ hdrs


----------------------------------------------------------------------
-- handlers

-- | TODO: currently, meta does not fail if idp does not exist.  should we change that behavior?
meta
  :: forall m err. (SPHandler (Error err) m, HasConfig m)
  => ST -> (IdPId -> m Issuer) -> (IdPId -> m URI)
  -> IdPId -> m SPMetadata
meta appName getRequestIssuer getResponseURI idpid = do
  enterH "meta"
  Issuer org <- getRequestIssuer idpid
  resp       <- getResponseURI idpid
  contacts   <- (^. cfgContacts) <$> getConfig
  Meta.mkSPMetadata appName org resp contacts

-- | Create authnreq, store it for comparison against assertions later, and return it in an HTTP
-- redirect together with the IdP's URI.
authreq
  :: (SPHandler (Error err) m)
  => NominalDiffTime -> (IdPId -> m Issuer)
  -> IdPId -> m (FormRedirect AuthnRequest)
authreq lifeExpectancySecs getIssuer idpid = do
  enterH "authreq"
  uri <- (^. idpMetadata . edRequestURI) <$> getIdPConfig idpid
  logger Debug $ "authreq uri: " <> cs (renderURI uri)
  req <- createAuthnRequest lifeExpectancySecs (getIssuer idpid)
  logger Debug $ "authreq req: " <> cs (encode req)
  leaveH $ FormRedirect uri req

-- | 'authreq' with request life expectancy defaulting to 8 hours.
authreq'
  :: (SPHandler (Error err) m)
  => (IdPId -> m Issuer)
  -> IdPId -> m (FormRedirect AuthnRequest)
authreq' = authreq (8 * 60 * 60)

-- | parse and validate response, and pass the verdict to a user-provided verdict handler.
authresp
  :: SPHandler (Error err) m
  => (IdPId -> m Issuer) -> (IdPId -> m URI) -> (AuthnResponse -> AccessVerdict -> m resp)
  -> IdPId -> AuthnResponseBody -> m resp
authresp getRequestIssuerURI getResponseURI handleVerdictAction idpid body = do
  enterH "authresp: entering"
  jctx :: JudgeCtx      <- JudgeCtx <$> getRequestIssuerURI idpid <*> getResponseURI idpid
  resp :: AuthnResponse <- fromAuthnResponseBody body
  logger Debug $ "authresp: " <> ppShow resp
  verdict <- judge resp jctx
  logger Debug $ "authresp: " <> show verdict
  handleVerdictAction resp verdict

-- | a variant of 'authresp' with a less general verdict handler.
authresp'
  :: SPHandler (Error err) m
  => (IdPId -> m Issuer) -> (IdPId -> m URI) -> HandleVerdict m
  -> IdPId -> AuthnResponseBody -> m (WithCookieAndLocation ST)
authresp' getRequestIssuerURI getResponseURI handleVerdict idpid body = do
  let handleVerdictAction resp verdict = case handleVerdict of
        HandleVerdictRedirect onsuccess -> simpleHandleVerdict onsuccess verdict
        HandleVerdictRaw action -> throwError . CustomServant =<< action resp verdict
  authresp getRequestIssuerURI getResponseURI handleVerdictAction idpid body


type OnSuccessRedirect m = UserRef -> m (Cky, URI)

type Cky = Cky.SimpleSetCookie CookieName
type CookieName = "saml2-web-sso"

simpleOnSuccess :: SPHandler (Error err) m => OnSuccessRedirect m
simpleOnSuccess uid = (Cky.toggleCookie "/" . Just . userRefToST $ uid,) . (^. cfgSPAppURI) <$> getConfig

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
      -> logger Info (show reasons) >> (throwError . Forbidden . cs $ ST.intercalate ", " reasons)
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
