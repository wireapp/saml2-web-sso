{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

-- | This is a sample application composed of the end-points in "SAML.WebSSO.API" plus a minimum of
-- functionality to make a running web application.  Some parts of this module could be handy to
-- build other apps, but it is more likely to serve as a tutorial.
module SAML2.WebSSO.API.Example where

import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import Lens.Micro
import Network.Wai hiding (Response)
import SAML2.WebSSO.API
import SAML2.WebSSO.Config
import SAML2.WebSSO.SP
import Servant.API hiding (URI(..))
import Servant.Server
import Servant.Utils.Enter
import Text.Hamlet.XML
import Text.XML.Util
import URI.ByteString
import Web.Cookie


-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: Application
app = app' (Proxy @Handler) ()

app' :: forall m.
        ( Enter (ServerT APPAPI m) m Handler (Server APPAPI)
        , SP m, SPHandler m
        ) => Proxy m -> NTCTX m -> Application
app' Proxy ctx = setHttpCachePolicy $ serve (Proxy @APPAPI) (enter (NT (nt @m ctx)) appapi :: Server APPAPI)

type SPAPI =
       Header "Cookie" SetCookie :> Get '[HTML] LoginStatus
  :<|> "logout" :> "local" :> GetVoid
  :<|> "logout" :> "single" :> GetVoid

type APPAPI =
       "sp"  :> SPAPI
  :<|> "sso" :> API

spapi :: SPHandler m => ServerT SPAPI m
spapi = loginStatus :<|> localLogout :<|> singleLogout

appapi :: SPHandler m => ServerT APPAPI m
appapi = spapi :<|> api "toy-sp"

loginStatus :: SP m => Maybe SetCookie -> m LoginStatus
loginStatus cookie = do
  loginPath  <- getPath' SsoPathAuthnReq
  logoutPath <- getPath' SpPathLocalLogout
  pure $ maybe (NotLoggedIn loginPath) (LoggedInAs logoutPath . cs . setCookieValue) cookie

-- | only logout on this SP.
localLogout :: SPHandler m => m Void
localLogout = (`redirect` [cookieToHeader $ togglecookie Nothing]) =<< getPath SpPathHome

-- | as in [3/4.4]
singleLogout :: (HasCallStack, SP m) => m Void
singleLogout = error "not implemented."

data LoginStatus = NotLoggedIn ST | LoggedInAs ST ST
  deriving (Eq, Show)

instance FromHttpApiData SetCookie where
  parseUrlPiece = headerValueToCookie

instance MimeRender HTML LoginStatus where
  mimeRender Proxy (NotLoggedIn loginPath)
    = mkHtml
      [xml|
        <body>
          [not logged in]
          <form action=#{loginPath} method="get">
            <input type="submit" value="login">
      |]
  mimeRender Proxy (LoggedInAs logoutPath name)
    = mkHtml
      [xml|
        <body>
        [logged in as #{name}]
          <form action=#{logoutPath} method="get">
            <input type="submit" value="logout">
          <p>
            (this is local logout; logout via IdP is not implemented.)
      |]


----------------------------------------------------------------------
-- uri paths

data Path = SpPathHome | SpPathLocalLogout | SpPathSingleLogout
          | SsoPathMeta | SsoPathAuthnReq | SsoPathAuthnResp
  deriving (Eq, Show)


getPath :: (HasConfig m, HasCallStack) => Path -> m URI
getPath = fmap unsafeParseURI . getPath'

getPath' :: forall m. (HasConfig m) => Path -> m ST
getPath' = fmap cs . \case
  SpPathHome         -> sp  ""
  SpPathLocalLogout  -> sp  "/logout/local"
  SpPathSingleLogout -> sp  "/logout/single"
  SsoPathMeta        -> sso "/meta"
  SsoPathAuthnReq    -> sso "/authreq"
  SsoPathAuthnResp   -> sso "/authresp"
  where
    sp  p = appendURI p . (^. cfgSPAppURI) <$> getConfig
    sso p = appendURI p . (^. cfgSPSsoURI) <$> getConfig
