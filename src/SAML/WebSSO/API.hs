{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE ViewPatterns          #-}

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
module SAML.WebSSO.API where

import Control.Monad.Except hiding (ap)
import Data.Binary.Builder (toLazyByteString)
import Data.EitherR
import Data.Function
import Data.List
import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import Lens.Micro
import Network.HTTP.Media ((//))
import Network.Wai hiding (Response)
import Network.Wai.Internal as Wai
import Servant.API.ContentTypes
import Servant.API hiding (URI)
import Servant.Multipart
import Servant.Server
import Text.Hamlet.XML
import Text.Show.Pretty (ppShow)
import Text.XML
import URI.ByteString
import Web.Cookie

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Network.HTTP.Types.Header as HttpTypes

import SAML.WebSSO.Config
import SAML.WebSSO.SP
import SAML.WebSSO.Types
import SAML.WebSSO.XML
import Text.XML.DSig


----------------------------------------------------------------------
-- examples app

-- TODO: move this section to "SAML.WebSSO.API.Example"

-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: Application
app = setHttpCachePolicy
    $ serve (Proxy @APPAPI) (hoistServer (Proxy @APPAPI) (nt @Handler) appapi :: Server APPAPI)

type SPAPI =
       Header "Cookie" SetCookie :> Get '[HTML] LoginStatus
  :<|> "logout" :> "local" :> GetVoid
  :<|> "logout" :> "single" :> GetVoid

type APPAPI =
       "sp"  :> SPAPI
  :<|> "sso" :> API

spapi :: (SP m, SPNT m) => ServerT SPAPI m
spapi = loginStatus :<|> localLogout :<|> singleLogout

appapi :: (SP m, SPNT m) => ServerT APPAPI m
appapi = spapi :<|> api

loginStatus :: SP m => Maybe SetCookie -> m LoginStatus
loginStatus = pure . maybe NotLoggedIn (LoggedInAs . cs . setCookieValue)

-- | only logout on this SP.
localLogout :: (SP m, SPNT m) => m Void
localLogout = redirect (getPath SpPathHome) [cookieToHeader $ togglecookie Nothing]

-- | as in [3/4.4]
singleLogout :: (HasCallStack, SP m) => m Void
singleLogout = error "not implemented."

data LoginStatus = NotLoggedIn | LoggedInAs ST
  deriving (Eq, Show)

instance FromHttpApiData SetCookie where
  parseUrlPiece = headerValueToCookie

instance MimeRender HTML LoginStatus where
  mimeRender Proxy NotLoggedIn
    = mkHtml
      [xml|
        <body>
          [not logged in]
          <form action=#{getPath' SsoPathAuthnReq} method="get">
            <input type="submit" value="login">
      |]
  mimeRender Proxy (LoggedInAs name)
    = mkHtml
      [xml|
        <body>
        [logged in as #{name}]
          <form action=#{getPath' SpPathLocalLogout} method="get">
            <input type="submit" value="logout">
          <p>
            (this is local logout; logout via IdP is not implemented.)
      |]


----------------------------------------------------------------------
-- saml web-sso api

type API = APIMeta :<|> APIAuthReq :<|> APIAuthResp

type APIMeta     = "meta" :> Get '[XML] EntityDescriptor
type APIAuthReq  = "authreq" :> Get '[HTML] (FormRedirect AuthnRequest)
type APIAuthResp = "authresp" :> MultipartForm Mem AuthnResponseBody :> PostVoid

-- FUTUREWORK: respond with redirect in case of success, instead of responding with Void and
-- handling all cases with exceptions: https://github.com/haskell-servant/servant/issues/117

api :: (SP m, SPNT m) => ServerT API m
api = meta :<|> authreq :<|> authresp


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


-- | An 'AuthnResponseBody' contains a 'AuthnResponse', but you need to give it a trust base forn
-- signature verification first, and you may get an error when you're looking at it.
newtype AuthnResponseBody = AuthnResponseBody ((ST -> RSA.PublicKey) -> Either ServantErr AuthnResponse)

instance FromMultipart Mem AuthnResponseBody where
  fromMultipart resp = Just . AuthnResponseBody $ \lookupPublicKey -> do
    base64 <- maybe (throwError err400 { errBody = "no SAMLResponse in the body" }) pure $
              lookupInput "SAMLResponse" resp
    xmltxt <- either (const $ throwError err400 { errBody = "bad base64 encoding in SAMLResponse" }) pure $
              EL.decode (cs base64)
    either (\ex -> throwError err400 { errBody = "invalid signature: " <> cs ex }) pure $
      simpleVerifyAuthnResponse lookupPublicKey xmltxt
    either (\ex -> throwError err400 { errBody = cs $ show ex }) pure $
      decode (cs xmltxt)


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
-- handlers

meta :: SP m => m EntityDescriptor
meta = do
  enterH "meta"
  undefined

authreq :: SP m => m (FormRedirect AuthnRequest)
authreq = do
  enterH "authreq"
  let uri = config ^. cfgIdPURI
  req <- createAuthnRequest
  leaveH $ FormRedirect uri req

authresp :: (SP m, SPNT m) => AuthnResponseBody -> m Void
authresp (AuthnResponseBody mkbody) = case mkbody undefined of
  Left err -> throwError err
  Right resp -> do
    enterH $ "authresp: " <> ppShow resp
    verdict <- judge resp
    logger $ show verdict

    case verdict of
      AccessDenied reasons
        -> logger (show reasons) >> reject
      AccessGranted uid
        -> redirect (getPath SpPathHome) [cookieToHeader . togglecookie . Just . cs . show $ uid]


----------------------------------------------------------------------
-- handler combinators

enterH :: SP m => String -> m ()
enterH msg =
  logger $ "entering handler: " <> msg

leaveH :: (Show a, SP m) => a -> m a
leaveH x = do
  logger $ "leaving handler: " <> show x
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
