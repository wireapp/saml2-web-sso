{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE ViewPatterns          #-}

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

import Control.Monad ((>=>))
import qualified Data.ByteString.Base64.Lazy as EL
import Data.EitherR
import Data.Function
import Data.List
import qualified Data.Map as Map
import Data.Proxy
import Data.String.Conversions
import qualified Data.Text as ST
import Lens.Micro
import Network.HTTP.Media ((//))
import Network.HTTP.Types.Header
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

import SAML.WebSSO.Config
import SAML.WebSSO.SP
import SAML.WebSSO.Types
import SAML.WebSSO.XML


----------------------------------------------------------------------
-- the api

type API = APIMeta :<|> APIAuthReq :<|> APIAuthResp

type APIMeta     = "meta" :> Get '[XML] EntityDescriptor
type APIAuthReq  = "authreq" :> Get '[HTML] (FormRedirect AuthnRequest)
type APIAuthResp = MultipartForm Mem AuthnResponseBody :> Post '[PlainText] String

api :: SP m => ServerT API m
api = meta :<|> authreq :<|> authresp

-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: Application
app = setHttpCachePolicy
    $ serve (Proxy @API) (hoistServer (Proxy @API) (nt @Handler) api :: Server API)


----------------------------------------------------------------------
-- servant plumbing

data XML

instance Accept XML where
  contentType Proxy = "application" // "xml"

instance HasXMLRoot a => MimeRender XML a where
  mimeRender Proxy = cs . encode

instance HasXMLRoot a => MimeUnrender XML a where
  mimeUnrender Proxy = fmapL show . decode . cs


data Void

instance AllCTRender '[] Void where
  handleAcceptH _ _ (_ :: Void) = error "impossible"


data HTML

instance  Accept HTML where
  contentType Proxy = "text" // "html"


newtype AuthnResponseBody = AuthnResponseBody AuthnResponse

instance FromMultipart Mem AuthnResponseBody where
  fromMultipart resp = AuthnResponseBody <$> (decodeBody =<< lookupInput "SAMLResponse" resp)
    where
      e2m = either (const Nothing) Just
      decodeBody = e2m . EL.decode . cs >=> e2m . decode . cs


-- | [2/3.5.4]
data FormRedirect xml = FormRedirect URI xml
  deriving (Eq, Show)

class HasXML xml => HasFormRedirect xml where
  formRedirectFieldName :: xml -> ST

instance HasFormRedirect AuthnRequest where
  formRedirectFieldName _ = "SAMLRequest"

instance HasXMLRoot xml => MimeRender HTML (FormRedirect xml) where
  mimeRender (Proxy :: Proxy HTML)
             (FormRedirect (cs . serializeURIRef' -> uri) (base64xml -> value))
    = renderLBS def doc
    where
      doc      = Document (Prologue [] (Just doctyp) []) root []
      doctyp   = Doctype "html" (Just $ PublicID "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd")
      root     = Element "html" rootattr html
      rootattr = Map.fromList [("xmlns", "http://www.w3.org/1999/xhtml"), ("xml:lang", "en")]

      html = [xml|
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

base64xml :: HasXMLRoot xml => xml -> ST
base64xml = break64 . cs . EL.encode . cs . encode
  where
    break64 t = case ST.splitAt 64 t of
      (x, "") -> x <> "\n"
      (x, x') -> x <> "\n" <> break64 x'


-- | [3.5.5.1] Caching
setHttpCachePolicy :: Middleware
setHttpCachePolicy ap rq respond = ap rq $ respond . addHeadersToResponse httpCachePolicy
  where
    httpCachePolicy :: ResponseHeaders
    httpCachePolicy = [("Cache-Control", "no-cache, no-store"), ("Pragma", "no-cache")]

    addHeadersToResponse ::  ResponseHeaders -> Wai.Response -> Wai.Response
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

authresp :: SP m => AuthnResponseBody -> m String
authresp (AuthnResponseBody resp) = do
  enterH $ "authresp: " <> ppShow resp
  pure (ppShow resp)


----------------------------------------------------------------------
-- handler combinators

enterH :: SP m => String -> m ()
enterH msg =
  logger $ "entering handler: " <> msg

leaveH :: (Show a, SP m) => a -> m a
leaveH x = do
  logger $ "leaving handler: " <> show x
  pure x
