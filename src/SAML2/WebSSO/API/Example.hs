{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

{-# OPTIONS_GHC -Wno-orphans #-}

-- | This is a sample application composed of the end-points in "SAML.WebSSO.API" plus a minimum of
-- functionality to make a running web application.  Some parts of this module could be handy to
-- build other apps, but it is more likely to serve as a tutorial.
module SAML2.WebSSO.API.Example where

import Control.Arrow ((&&&))
import Control.Concurrent.MVar
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Writer
import Data.EitherR (fmapL)
import Data.Map as Map
import Data.Proxy
import Data.String.Conversions
import Data.UUID as UUID
import GHC.Stack
import Lens.Micro
import Network.Wai hiding (Response)
import SAML2.Util
import SAML2.WebSSO
import Servant.API hiding (URI(..))
import Servant.Server
import Text.Hamlet.XML
import Text.XML
import URI.ByteString


-- | The most straight-forward 'Application' that can be constructed from 'api', 'API'.
app :: IO Application
app = app' (Proxy @SimpleSP) =<< mkSimpleSPCtx =<< configIO

app'
  :: forall (m :: * -> *). (SP m, SPHandler SimpleError m)
  => Proxy m -> NTCTX m -> IO Application
app' Proxy ctx = do
  let served :: Application
      served = serve (Proxy @APPAPI)
                   (hoistServer (Proxy @APPAPI) (nt @SimpleError @m ctx) appapi :: Server APPAPI)
  pure . setHttpCachePolicy $ served

type SPAPI =
       Header "Cookie" Cky :> Get '[HTML] LoginStatus
  :<|> "logout" :> "local" :> GetRedir '[HTML] (WithCookieAndLocation ST)
  :<|> "logout" :> "single" :> GetRedir '[HTML] (WithCookieAndLocation ST)

type APPAPI =
       "sp"  :> SPAPI
  :<|> "sso" :> API

spapi :: SPHandler SimpleError m => ServerT SPAPI m
spapi = loginStatus :<|> localLogout :<|> singleLogout

appapi :: SPHandler SimpleError m => ServerT APPAPI m
appapi = spapi :<|> api "toy-sp" (HandleVerdictRedirect simpleOnSuccess)

loginStatus :: SP m => Maybe Cky -> m LoginStatus
loginStatus cookie = do
  idpids     <- _
  loginOpts  <- mkLoginOption `mapM` idpids
  logoutPath <- getPath' SpPathLocalLogout
  pure $ maybe (NotLoggedIn loginOpts) (LoggedInAs logoutPath . cs . setSimpleCookieValue) cookie

mkLoginOption :: SP m => IdPConfig a -> m (ST, ST)
mkLoginOption icfg = (renderURI $ icfg ^. idpMetadata . edIssuer . fromIssuer,) <$> getPath' (SsoPathAuthnReq (icfg ^. idpId))

-- | only logout on this SP.
localLogout :: SPHandler SimpleError m => m (WithCookieAndLocation ST)
localLogout = do
  uri <- getPath SpPathHome
  cky <- toggleCookie "/" Nothing
  pure . addHeader cky . addHeader uri $ "Logged out locally, redirecting to " <> renderURI uri

-- | as in [3/4.4]
singleLogout :: (HasCallStack, SP m) => m (WithCookieAndLocation ST)
singleLogout = error "not implemented."

data LoginStatus
  = NotLoggedIn [(ST{- issuer -}, ST{- authreq path -})]
  | LoggedInAs ST ST
  deriving (Eq, Show)

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
-- a simple concrete monad

newtype SimpleSP a = SimpleSP (ReaderT SimpleSPCtx (ExceptT SimpleError IO) a)
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader SimpleSPCtx, MonadError SimpleError)

type SimpleSPCtx = (Config, MVar RequestStore, MVar AssertionStore)
type RequestStore = Map.Map (ID AuthnRequest) Time
type AssertionStore = Map.Map (ID Assertion) Time

-- | If you read the 'Config' initially in 'IO' and then pass it into the monad via 'Reader', you
-- safe disk load and redundant debug logs.
instance SPHandler SimpleError SimpleSP where
  type NTCTX SimpleSP = SimpleSPCtx
  nt ctx (SimpleSP m) = Handler . ExceptT . fmap (fmapL toServantErr) . runExceptT $ m `runReaderT` ctx

mkSimpleSPCtx :: Config -> IO SimpleSPCtx
mkSimpleSPCtx cfg = (,,) cfg <$> newMVar mempty <*> newMVar mempty

instance SP SimpleSP where
  logger level msg = getConfig >>= \cfg -> SimpleSP (loggerIO (cfg ^. cfgLogLevel) level msg)
  createUUID       = SimpleSP $ createUUIDIO
  getNow           = SimpleSP $ getNowIO

simpleStoreID
  :: (MonadIO m, MonadReader ctx m)
  => Lens' ctx (MVar (Map (ID a) Time)) -> ID a -> Time -> m ()
simpleStoreID sel item endOfLife = do
  store <- asks (^. sel)
  liftIO $ modifyMVar_ store (pure . simpleStoreID' item endOfLife)

simpleStoreID' :: ID a -> Time -> Map (ID a) Time -> Map (ID a) Time
simpleStoreID' = Map.insert

simpleUnStoreID
  :: (MonadIO m, MonadReader ctx m)
  => Lens' ctx (MVar (Map (ID a) Time)) -> (ID a) -> m ()
simpleUnStoreID sel item = do
  store <- asks (^. sel)
  liftIO $ modifyMVar_ store (pure . simpleUnStoreID' item)

simpleUnStoreID' :: ID a -> Map (ID a) Time -> Map (ID a) Time
simpleUnStoreID' = Map.delete

simpleIsAliveID
  :: (MonadIO m, MonadReader ctx m, SP m)
  => Lens' ctx (MVar (Map (ID a) Time)) -> ID a -> m Bool
simpleIsAliveID sel item = do
  now <- getNow
  store <- asks (^. sel)
  items <- liftIO $ readMVar store
  pure $ simpleIsAliveID' now item items

simpleIsAliveID' :: Time -> ID a -> Map (ID a) Time -> Bool
simpleIsAliveID' now item items = maybe False (>= now) (Map.lookup item items)


instance SPStoreID AuthnRequest SimpleSP where
  storeID   = simpleStoreID   (_2)
  unStoreID = simpleUnStoreID (_2)
  isAliveID = simpleIsAliveID (_2)

instance SPStoreID Assertion SimpleSP where
  storeID   = simpleStoreID   (_3)
  unStoreID = simpleUnStoreID (_3)
  isAliveID = simpleIsAliveID (_3)

instance HasConfig SimpleSP where
  getConfig = (^. _1) <$> SimpleSP ask

instance SPStoreIdP SimpleError SimpleSP where
  type IdPConfigExtra SimpleSP = ()
  storeIdPConfig _ = pure ()
  getIdPConfig = simpleGetIdPConfigBy (^. idpId)
  getIdPConfigByIssuer = simpleGetIdPConfigBy (^. idpMetadata . edIssuer)

simpleGetIdPConfigBy :: (MonadError (Error err) m, HasConfig m, Show a, Ord a)
                     => (IdPConfig (IdPConfigExtra m) -> a) -> a -> m (IdPConfig (IdPConfigExtra m))
simpleGetIdPConfigBy mkkey idpname = maybe crash' pure . Map.lookup idpname . mkmap . _ =<< getConfig
  where
    crash' = throwError (UnknownIdP . cs . show $ idpname)
    mkmap = Map.fromList . fmap (mkkey &&& id)


----------------------------------------------------------------------
-- uri paths

data Path = SpPathHome | SpPathLocalLogout | SpPathSingleLogout
          | SsoPathMeta IdPId | SsoPathAuthnReq IdPId | SsoPathAuthnResp IdPId
  deriving (Eq, Show)


getPath' :: forall m. (HasConfig m) => Path -> m ST
getPath' = fmap renderURI . getPath

getPath :: forall m. (HasConfig m) => Path -> m URI
getPath path = do
  cfg <- getConfig

  let sp, sso :: ST -> URI
      sp = ((cfg ^. cfgSPAppURI) =/)
      sso = ((cfg ^. cfgSPSsoURI) =/)

      withidp :: IdPId -> URI -> URI
      withidp (IdPId uuid) = (=/ UUID.toText uuid)

  pure $ case path of
    SpPathHome          -> sp  ""
    SpPathLocalLogout   -> sp  "/logout/local"
    SpPathSingleLogout  -> sp  "/logout/single"
    SsoPathMeta ip      -> withidp ip $ sso "/meta"
    SsoPathAuthnReq ip  -> withidp ip $ sso "/authreq"
    SsoPathAuthnResp ip -> withidp ip $ sso "/authresp"
