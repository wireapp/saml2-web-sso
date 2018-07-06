{-# LANGUAGE OverloadedStrings #-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module TestSP where

import Control.Concurrent.MVar
import Control.Exception (throwIO, ErrorCall(..))
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.State
import Data.EitherR
import Data.String.Conversions
import Data.Yaml
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO
import Servant.Server
import URI.ByteString.QQ
import Util


----------------------------------------------------------------------

data Ctx = Ctx
  { _ctxNow            :: Time
  , _ctxConfig         :: Config_
  , _ctxAssertionStore :: MVar AssertionStore
  , _ctxRequestStore   :: MVar RequestStore
  }

instance Show Ctx where
  show (Ctx n c _ _) = "(Ctx " <> show (n, c) <> ")"

makeLenses ''Ctx

mkTestCtx1 :: IO Ctx
mkTestCtx1 = do
  let _ctxNow         = timeNow
      _ctxConfig      = fallbackConfig & cfgLogLevel .~ Fatal
                                       & cfgSPAppURI .~ [uri|https://zb2.zerobuzz.net:60443/|]
                                       & cfgSPSsoURI .~ [uri|https://zb2.zerobuzz.net:60443/|]
  _ctxAssertionStore <- newMVar mempty
  _ctxRequestStore <- newMVar mempty
  pure Ctx {..}

-- | Use this to see more output on a per-test basis.
verbose :: Ctx -> Ctx
verbose = ctxConfig . cfgLogLevel .~ Debug

mkTestCtx2 :: IO Ctx
mkTestCtx2 = do
  myidp <- mkmyidp
  testCtx1 <- mkTestCtx1
  pure $ testCtx1 & ctxConfig . cfgIdps .~ [myidp]

mkmyidp :: IO IdPConfig_
mkmyidp = do
  either error id . decodeEither . cs <$> readSampleIO "microsoft-idp-config.yaml"

mkTestCtx3 :: IO Ctx
mkTestCtx3 = mkTestCtx2
  <&> ctxNow .~ unsafeReadTime "2018-03-11T17:14:13Z"
  <&> ctxConfig . cfgSPSsoURI .~ [uri|https://zb2.zerobuzz.net:60443/|]

timeLongAgo     :: Time
timeLongAgo     = unsafeReadTime "1918-04-14T09:58:58.457Z"

timeNow         :: Time
timeNow         = unsafeReadTime "2018-03-11T17:13:13Z"

timeIn10minutes :: Time
timeIn10minutes = unsafeReadTime "2018-03-11T17:23:00.01Z"

timeIn20minutes :: Time
timeIn20minutes = unsafeReadTime "2018-03-11T17:33:00Z"


newtype TestSP a = TestSP { runTestSP :: StateT Ctx (ExceptT SimpleError IO) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState Ctx, MonadError SimpleError)

instance HasConfig TestSP where
  type ConfigExtra TestSP = ()
  getConfig = gets (^. ctxConfig)

instance SP TestSP where
  getNow = gets (^. ctxNow)

instance SPStore TestSP where
  storeRequest req keepAroundUntil = do
    store <- gets (^. ctxRequestStore)
    simpleStoreRequest store req keepAroundUntil

  checkAgainstRequest req = do
    store <- gets (^. ctxRequestStore)
    now <- getNow
    simpleCheckAgainstRequest store req now

  storeAssertion aid time = do
    store <- gets (^. ctxAssertionStore)
    now <- getNow
    simpleStoreAssertion store now aid time

instance SPStoreIdP SimpleError TestSP where
  storeIdPConfig _ = pure ()
  getIdPConfig = simpleGetIdPConfigBy (^. idpId)
  getIdPConfigByIssuer = simpleGetIdPConfigBy (^. idpIssuer)

instance SPHandler SimpleError TestSP where
  type NTCTX TestSP = Ctx

  nt :: forall x. Ctx -> TestSP x -> Handler x
  nt = handlerFromTestSP

handlerFromTestSP :: Ctx -> TestSP a -> Handler a
handlerFromTestSP ctx (TestSP m) = Handler . ExceptT . fmap (fmapL toServantErr) . runExceptT $ m `evalStateT` ctx

ioFromTestSP :: Ctx -> TestSP a -> IO a
ioFromTestSP ctx m = either (throwIO . ErrorCall . show) pure =<< (runExceptT . runHandler' $ handlerFromTestSP ctx m)


----------------------------------------------------------------------

newtype TestSPStoreIdP a = TestSPStoreIdP { runTestSPStoreIdP :: ExceptT SimpleError (Reader (Maybe IdPConfig_)) a }
  deriving (Functor, Applicative, Monad, MonadReader (Maybe IdPConfig_), MonadError SimpleError)

instance HasConfig TestSPStoreIdP where
  type ConfigExtra TestSPStoreIdP = ()
  getConfig = error "n/a"

instance SPStoreIdP SimpleError TestSPStoreIdP where
  storeIdPConfig = error "n/a"
  getIdPConfig = error "n/a"
  getIdPConfigByIssuer _ = maybe (throwError $ UnknownIdP "<n/a>") pure =<< ask
