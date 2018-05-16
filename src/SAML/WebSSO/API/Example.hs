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

-- | This is a sample application composed of the end-points in "SAML.WebSSO.API" plus a minimum of
-- functionality to make a running web application.  Some parts of this module could be handy to
-- build other apps, but it is more likely to serve as a tutorial.
module SAML.WebSSO.API.Example where

import Control.Lens
import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import Network.Wai hiding (Response)
import SAML.WebSSO.API
import SAML.WebSSO.Config
import SAML.WebSSO.SP
import Servant.API hiding (URI(..))
import Servant.Server
import Text.Hamlet.XML
import Text.XML.Util
import URI.ByteString
import Web.Cookie


-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: Application
app = setHttpCachePolicy
    $ serve (Proxy @APPAPI) (hoistServer (Proxy @APPAPI) (nt @Handler ()) appapi :: Server APPAPI)

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
appapi = spapi :<|> api "toy-sp"

loginStatus :: SP m => Maybe SetCookie -> m LoginStatus
loginStatus cookie = do
  loginPath  <- getPath' SsoPathAuthnReq
  logoutPath <- getPath' SpPathLocalLogout
  pure $ maybe (NotLoggedIn loginPath) (LoggedInAs logoutPath . cs . setCookieValue) cookie

-- | only logout on this SP.
localLogout :: (SP m, SPNT m) => m Void
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
