{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

-- | This is a sample application composed of the end-points in "SAML.WebSSO.API" plus a minimum of
-- functionality to make a running web application.  Some parts of this module could be handy to
-- build other apps, but it is more likely to serve as a tutorial.
module SAML2.WebSSO.API.Example where

import Data.Proxy
import Data.String.Conversions
import Data.UUID as UUID
import GHC.Stack
import Lens.Micro
import Network.Wai hiding (Response)
import SAML2.WebSSO
import Servant.API hiding (URI(..))
import Servant.Server
import Text.Hamlet.XML
import Text.XML
import Text.XML.Util
import URI.ByteString
import Web.Cookie


-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: IO Application
app = app' (Proxy @SimpleSP) =<< mkSimpleSPCtx =<< configIO

app' :: forall (m :: * -> *).
        ( SP m, SPHandler SimpleError m
        ) => Proxy m -> NTCTX m -> IO Application
app' Proxy ctx = do
  let served :: Application
      served = serve (Proxy @APPAPI) (hoistServer (Proxy @APPAPI) (nt @SimpleError @m ctx) appapi :: Server APPAPI)
  pure . setHttpCachePolicy $ served

type SPAPI =
       Header "Cookie" SetCookie :> Get '[HTML] LoginStatus
  :<|> "logout" :> "local" :> GetRedir '[HTML] (WithCookieAndLocation ST)
  :<|> "logout" :> "single" :> GetRedir '[HTML] (WithCookieAndLocation ST)

type APPAPI =
       "sp"  :> SPAPI
  :<|> "sso" :> API

spapi :: SPHandler SimpleError m => ServerT SPAPI m
spapi = loginStatus :<|> localLogout :<|> singleLogout

appapi :: SPHandler SimpleError m => ServerT APPAPI m
appapi = spapi :<|> api "toy-sp" simpleOnSuccess

loginStatus :: SP m => Maybe SetCookie -> m LoginStatus
loginStatus cookie = do
  idpids     <- (^. cfgIdps) <$> getConfig
  loginOpts  <- mkLoginOption `mapM` idpids
  logoutPath <- getPath' SpPathLocalLogout
  pure $ maybe (NotLoggedIn loginOpts) (LoggedInAs logoutPath . cs . setCookieValue) cookie

mkLoginOption :: SP m => IdPConfig a -> m (ST, ST)
mkLoginOption icfg = (renderURI $ icfg ^. idpIssuer . fromIssuer,) <$> getPath' (SsoPathAuthnReq (icfg ^. idpId))

-- | only logout on this SP.
localLogout :: SPHandler SimpleError m => m (WithCookieAndLocation ST)
localLogout = do
  uri <- getPath SpPathHome
  pure . addHeader (togglecookie Nothing) . addHeader uri $ "Logged out locally, redirecting to " <> renderURI uri

-- | as in [3/4.4]
singleLogout :: (HasCallStack, SP m) => m (WithCookieAndLocation ST)
singleLogout = error "not implemented."

data LoginStatus
  = NotLoggedIn [(ST{- issuer -}, ST{- authreq path -})]
  | LoggedInAs ST ST
  deriving (Eq, Show)

instance FromHttpApiData SetCookie where
  parseUrlPiece = headerValueToCookie

instance MimeRender HTML LoginStatus where
  mimeRender Proxy (NotLoggedIn loginOpts)
    = mkHtml
      [xml|
        <body>
          [not logged in]
          $forall loginOpt <- loginOpts
            ^{mkform loginOpt}
      |]
      where
        mkform :: (ST, ST) -> [Node]
        mkform (issuer, path) =
          [xml|
            <form action=#{path} method="get">
              <input type="submit" value="log in via #{issuer}">
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
          | SsoPathMeta | SsoPathAuthnReq IdPId | SsoPathAuthnResp
  deriving (Eq, Show)


getPath :: (HasConfig m, HasCallStack) => Path -> m URI
getPath = fmap unsafeParseURI . getPath'

getPath' :: forall m. (HasConfig m) => Path -> m ST
getPath' = fmap cs . \case
  SpPathHome         -> sp  ""
  SpPathLocalLogout  -> sp  "/logout/local"
  SpPathSingleLogout -> sp  "/logout/single"
  SsoPathMeta        -> sso "/meta"
  SsoPathAuthnReq ip -> sso "/authreq" <&> withidp ip
  SsoPathAuthnResp   -> sso "/authresp"
  where
    sp  p = appendURI p . (^. cfgSPAppURI) <$> getConfig
    sso p = appendURI p . (^. cfgSPSsoURI) <$> getConfig
    withidp (IdPId uuid) = (<> ("/" <> cs (UUID.toString uuid)))
