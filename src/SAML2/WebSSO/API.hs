{-# LANGUAGE OverloadedStrings #-}

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
import Data.Binary.Builder (toLazyByteString)
import Data.EitherR
import Data.Function
import Data.List
import Data.Maybe (catMaybes)
import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import Lens.Micro
import Network.HTTP.Media ((//))
import Network.Wai hiding (Response)
import Network.Wai.Internal as Wai
import SAML2.WebSSO.Config
import SAML2.WebSSO.SP
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Servant.API.ContentTypes
import Servant.API hiding (URI(..))
import Servant.Multipart
import Servant.Server
import Text.Hamlet.XML
import Text.Show.Pretty (ppShow)
import Text.XML
import Text.XML.Cursor
import Text.XML.DSig (SignCreds(SignCreds), SignDigest(SignDigestSha256), SignKey(SignKeyRSA), verify, keyInfoToCreds)
import Text.XML.Util
import URI.ByteString
import Web.Cookie

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Network.HTTP.Types.Header as HttpTypes
import qualified SAML2.WebSSO.XML.Meta as Meta


----------------------------------------------------------------------
-- saml web-sso api

type API = APIMeta'
      :<|> APIAuthReq'
      :<|> APIAuthResp'

type APIMeta     = Get '[XML] Meta.SPDesc
type APIAuthReq  = Capture "idp" IdPId :> Get '[HTML] (FormRedirect AuthnRequest)
type APIAuthResp = MultipartForm Mem AuthnResponseBody :> PostVoid

-- NB: 'APIAuthResp' cannot easily be enhanced with a @Capture "idp" IdPId@ path segment like
-- 'APIAuthReq'.  The reason is a design flag in the standard: the meta information end-point must
-- provide the response end-point URL to any client, and it would not be clear which IdP to include
-- there.  So instead we need to accept responses from any IdP on the same URI, and rely on the
-- information from the response body only to recover our internal spar IdP handle.

-- FUTUREWORK: respond with redirect in case of success, instead of responding with Void and
-- handling all cases with exceptions: https://github.com/haskell-servant/servant/issues/117

type APIMeta'     = "meta" :> APIMeta
type APIAuthReq'  = "authreq" :> APIAuthReq
type APIAuthResp' = "authresp" :> APIAuthResp

api :: SPHandler m => ST -> (UserRef -> m Void) -> ServerT API m
api appName onsuccess = meta appName (Proxy @API) (Proxy @APIAuthResp')
                   :<|> authreq
                   :<|> authresp onsuccess


----------------------------------------------------------------------
-- authentication response body processing

-- | An 'AuthnResponseBody' contains a 'AuthnResponse', but you need to give it a trust base forn
-- signature verification first, and you may get an error when you're looking at it.
newtype AuthnResponseBody = AuthnResponseBody { fromAuthnResponseBody :: forall m. SPStoreIdP m => m AuthnResponse }

parseAuthnResponseBody :: forall m. SPStoreIdP m => LBS -> m AuthnResponse
parseAuthnResponseBody base64 = do
  xmltxt <-
    either (const $ throwError err400 { errBody = "bad base64 encoding in SAMLResponse" }) pure $
    EL.decode base64
  resp <-
    either (\ex -> throwError err400 { errBody = cs $ show ex }) pure $
    decode (cs xmltxt)
  simpleVerifyAuthnResponse (resp ^. rspIssuer) xmltxt
  pure resp


-- | Pull assertions sub-forest and pass all trees in it to 'verify' individually.  The 'LBS'
-- argument must be a valid 'AuthnResponse'.  All assertions need to be signed by the issuer
-- given in the arguments using the same key.
simpleVerifyAuthnResponse :: forall m. SPStoreIdP m => Maybe Issuer -> LBS -> m ()
simpleVerifyAuthnResponse Nothing _ = throwError err400 { errBody = "missing issuer in response." }
simpleVerifyAuthnResponse (Just issuer) raw = do
    creds <- (^. idpPublicKey) <$> getIdPConfigByIssuer issuer
    key :: RSA.PublicKey <- case keyInfoToCreds creds of
        Right (SignCreds SignDigestSha256 (SignKeyRSA k)) -> pure k
        Left msg -> throwError err500 { errBody = "IdP pubkey corrupted in SP config: " <> cs (show msg) }

    doc :: Cursor <- either (\msg -> throwError err400 { errBody = "could not parse document: " <> cs (show msg) })
                            (pure . fromDocument)
                            (parseLBS def raw)

    let elemOnly (NodeElement el) = Just el
        elemOnly _ = Nothing

        assertions :: [Element]
        assertions = catMaybes $ elemOnly . node <$>
                     (doc $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    when (null assertions) $
      throwError err400 { errBody = "no assertions: " <> cs (show raw) }

    let assertionID :: Element -> m String
        assertionID el@(Element _ attrs _)
          = maybe (throwError err400 { errBody = "assertion without ID: " <> cs (show el) }) (pure . cs)
          $ Map.lookup "ID" attrs
    nodeids :: [String]
      <- assertionID `mapM` assertions

    either (\msg -> throwError err400 { errBody = cs msg }) pure $ (verify key raw `mapM_` nodeids)


----------------------------------------------------------------------
-- servant, wai plumbing

type GetVoid  = Get  '[HTML, JSON, XML] Void
type PostVoid = Post '[HTML, JSON, XML] Void


data XML

instance Accept XML where
  contentType Proxy = "application" // "xml"

instance {-# OVERLAPPABLE #-} HasXMLRoot a => MimeRender XML a where
  mimeRender Proxy = cs . encode

instance {-# OVERLAPPABLE #-} HasXMLRoot a => MimeUnrender XML a where
  mimeUnrender Proxy = fmapL show . decode . cs


data Void

instance MimeRender HTML Void where
  mimeRender Proxy = error "absurd"

instance {-# OVERLAPS #-} MimeRender JSON Void where
  mimeRender Proxy = error "absurd"

instance {-# OVERLAPS #-} MimeRender XML Void where
  mimeRender Proxy = error "absurd"


data HTML

instance  Accept HTML where
  contentType Proxy = "text" // "html"


instance FromMultipart Mem AuthnResponseBody where
  fromMultipart resp = Just (AuthnResponseBody eval)
    where
      eval :: forall m. SPStoreIdP m => m AuthnResponse
      eval = do
        base64 <- maybe (throwError err400 { errBody = "no SAMLResponse in the body" }) pure $
                  lookupInput "SAMLResponse" resp
        parseAuthnResponseBody (cs base64)


-- | [2/3.5.4]
data FormRedirect xml = FormRedirect URI xml
  deriving (Eq, Show)

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

mkHtml :: [Node] -> LBS
mkHtml nodes = renderLBS def doc
  where
    doc      = Document (Prologue [] (Just doctyp) []) root []
    doctyp   = Doctype "html" (Just $ PublicID "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd")
    root     = Element "html" rootattr nodes
    rootattr = Map.fromList [("xmlns", "http://www.w3.org/1999/xhtml"), ("xml:lang", "en")]


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
-- paths

getResponseURI :: forall m endpoint api.
                  ( HasCallStack, SP m
                  , MonadError ServantErr m
                  , IsElem endpoint api, HasLink endpoint, ToHttpApiData (MkLink endpoint)
                  )
               => Proxy api -> Proxy endpoint -> m URI
getResponseURI proxyAPI proxyAPIAuthResp = resp =<< (^. cfgSPSsoURI) <$> getConfig
  where
    resp :: URI -> m URI
    resp uri = either showmsg pure (parseURI' uri')
      where
        uri' :: ST
        uri' = cs $ appendURI (cs . toUrlPiece $ safeLink proxyAPI proxyAPIAuthResp) uri

        showmsg :: String -> m a
        showmsg msg = throwError err500 { errBody = "server configuration error: " <> cs (show (uri', msg)) }


----------------------------------------------------------------------
-- handlers

meta :: (SPHandler m, IsElem endpoint api, HasLink endpoint, ToHttpApiData (MkLink endpoint))
     => ST -> Proxy api -> Proxy endpoint -> m Meta.SPDesc
meta appName proxyAPI proxyAPIAuthResp = do
  enterH "meta"
  landing <- getLandingURI
  resp <- getResponseURI proxyAPI proxyAPIAuthResp
  contacts <- (^. cfgContacts) <$> getConfig
  Meta.spMeta <$> Meta.spDesc appName landing resp contacts

authreq :: (SPStoreIdP m, SPHandler m) => IdPId -> m (FormRedirect AuthnRequest)
authreq idpname = do
  enterH "authreq"
  uri <- (^. idpRequestUri) <$> getIdPConfig idpname
  logger DEBUG $ "authreq uri: " <> cs (renderURI uri)
  req <- createAuthnRequest
  logger DEBUG $ "authreq req: " <> show req
  leaveH $ FormRedirect uri req

simpleOnSuccess :: SPHandler m => UserRef -> m Void
simpleOnSuccess uid = getLandingURI >>= (`redirect` [cookieToHeader . togglecookie . Just . cs . show $ uid])

authresp :: SPHandler m => (UserRef -> m Void) -> AuthnResponseBody -> m Void
authresp onsuccess body = do
  enterH "authresp: entering"
  resp <- fromAuthnResponseBody body
  logger DEBUG $ "authresp: " <> ppShow resp
  verdict <- judge resp
  logger DEBUG $ "authresp: " <> show verdict
  case verdict of
    AccessDenied reasons
      -> logger INFO (show reasons) >> reject (cs $ ST.intercalate ", " reasons)
    AccessGranted uid
      -> onsuccess uid


-- TODO: it's weird that we have IdPs in the config.  remove that entirely?


----------------------------------------------------------------------
-- handler combinators

crash :: (SP m, MonadError ServantErr m) => String -> m a
crash msg = do
  logger CRITICAL msg
  throwError err500 { errBody = "internal error: consult server logs." }

enterH :: SP m => String -> m ()
enterH msg =
  logger DEBUG $ "entering handler: " <> msg

leaveH :: (Show a, SP m) => a -> m a
leaveH x = do
  logger DEBUG $ "leaving handler: " <> show x
  pure x


----------------------------------------------------------------------
-- cookies

cookiename :: SBS
cookiename = "saml2-web-sso_sp_credentials"

togglecookie :: Maybe ST -> SetCookie
togglecookie = \case
  Just nick -> cookie
    { setCookieValue = cs nick
    }
  Nothing -> cookie
    { setCookieValue = ""
    , setCookieExpires = Just . fromTime $ unsafeReadTime "1970-01-01T00:00:00Z"
    , setCookieMaxAge = Just (-1)
    }
  where
    cookie = defaultSetCookie
      { setCookieName = cookiename
      , setCookieSecure = True
      , setCookiePath = Just "/"
      }

cookieToHeader :: SetCookie -> HttpTypes.Header
cookieToHeader = ("set-cookie",) . cs . toLazyByteString . renderSetCookie

headerValueToCookie :: ST -> Either ST SetCookie
headerValueToCookie txt = do
  let cookie = parseSetCookie $ cs txt
  case ["missing cookie name"  | setCookieName cookie == ""] <>
       ["wrong cookie name"    | setCookieName cookie /= cookiename] <>
       ["missing cookie value" | setCookieValue cookie == ""]
    of errs@(_:_) -> throwError $ ST.intercalate ", " errs
       []         -> pure cookie
