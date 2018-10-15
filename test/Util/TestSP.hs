{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Util.TestSP where

import Control.Concurrent.MVar
import Control.Exception (throwIO, ErrorCall(..))
import Control.Monad.Except
import Control.Monad.Reader
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe
import Data.Time
import Data.UUID as UUID
import GHC.Stack
import Lens.Micro
import Network.Wai.Test (runSession)
import SAML2.WebSSO
import SAML2.WebSSO.API.Example (simpleGetIdPConfigBy)
import SAML2.WebSSO.Test.Credentials
import Servant
import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.Internal (unWaiSession)
import URI.ByteString.QQ
import Util.Types

import qualified Data.Map as Map


mkTestCtxSimple :: MonadIO m => m CtxV
mkTestCtxSimple = liftIO $ do
  let _ctxNow            = timeNow  -- constant time value, see below
      _ctxConfig         = fallbackConfig & cfgLogLevel .~ Fatal
      _ctxAssertionStore = mempty
      _ctxRequestStore   = mempty
  newMVar Ctx {..}

mkTestCtxWithIdP :: MonadIO m => m CtxV
mkTestCtxWithIdP = liftIO $ do
  ctxmv <- mkTestCtxSimple
  liftIO $ modifyMVar_ ctxmv (pure . (ctxConfig . cfgIdps .~ [testIdPConfig]))
  pure ctxmv

testIdPConfig :: IdPConfig_
testIdPConfig = IdPConfig {..}
  where
    _idpId               = IdPId . fromJust . UUID.fromText $ "035ed888-c196-11e8-8278-7b25a2639572"
    _idpMetadata         = IdPMetadata {..}
    _edIssuer            = Issuer [uri|http://sample-idp.com/issuer|]
    _edRequestURI        = [uri|http://sample-idp.com/request|]
    _edCertAuthnResponse = sampleIdPCert :| []
    _idpExtraInfo        = ()

mkTestSPMetadata :: HasConfig m => m SPMetadata
mkTestSPMetadata = do
  let _spID             = ID "_4b7e1488-c0c6-11e8-aef0-9fe604f9513a"
      _spValidUntil     = fromTime $ addTime (60 * 60 * 24 * 365) timeNow
      _spCacheDuration  = 2592000
      _spOrgName        = "drnick"
      _spOrgDisplayName = "drnick"
      _spContacts       = fallbackContact :| []
  _spOrgURL            <- (^. fromIssuer) <$> defSPIssuer
  _spResponseURL       <- defResponseURI
  pure SPMetadata {..}


-- | Use this to see more output on a per-test basis.
verbose :: Ctx -> Ctx
verbose = ctxConfig . cfgLogLevel .~ Debug


timeLongAgo     :: Time
timeLongAgo     = unsafeReadTime "1918-04-14T09:58:58.457Z"

timeNow         :: Time
timeNow         = unsafeReadTime "2018-03-11T17:13:13Z"

timeIn10minutes :: Time
timeIn10minutes = unsafeReadTime "2018-03-11T17:23:00.01Z"

timeIn20minutes :: Time
timeIn20minutes = unsafeReadTime "2018-03-11T17:33:00Z"

modifyCtx :: (HasCallStack, MonadIO m, MonadReader CtxV m) => (Ctx -> (Ctx, a)) -> m a
modifyCtx f = do
  ctx <- ask
  liftIO $ modifyMVar ctx (pure . f)

modifyCtx_ :: (HasCallStack, MonadIO m, MonadReader CtxV m) => (Ctx -> Ctx) -> m ()
modifyCtx_ = modifyCtx . ((, ()) .)

-- | run an action at a time specified relative to now.
timeTravel :: (HasCallStack, MonadIO m, MonadReader CtxV m) => NominalDiffTime -> m a -> m a
timeTravel distance action = do
  let mv dist_ = modifyCtx_ (ctxNow %~ (dist_ `addTime`))
  mv distance
  result <- action
  mv (-distance)
  pure result


newtype TestSP a = TestSP { runTestSP :: ReaderT CtxV (ExceptT SimpleError IO) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader CtxV, MonadError SimpleError)

instance HasConfig TestSP where
  type ConfigExtra TestSP = ()
  getConfig = (^. ctxConfig) <$> (liftIO . readMVar =<< ask)

instance SP TestSP where
  -- Make TestSP to move forward in time after each look at the clock.
  getNow = modifyCtx (\ctx -> (ctx & ctxNow %~ (1 `addTime`), ctx ^. ctxNow))

instance SPStore TestSP where
  storeRequest req keepAroundUntil = do
    modifyCtx_ (ctxRequestStore %~ Map.insert req keepAroundUntil)

  checkAgainstRequest req = do
    now <- getNow
    reqs <- modifyCtx (\ctx -> (ctx, ctx ^. ctxRequestStore))
    pure $ Map.lookup req reqs > Just now

  storeAssertion aid time = do
    now <- getNow
    modifyCtx $ \ctx -> ( ctx & ctxAssertionStore %~ Map.insert aid time
                        , case Map.lookup aid (ctx ^. ctxAssertionStore) of
                            Just time' -> time' < now
                            Nothing -> True
                        )

instance SPStoreIdP SimpleError TestSP where
  storeIdPConfig _ = pure ()
  getIdPConfig = simpleGetIdPConfigBy (^. idpId)
  getIdPConfigByIssuer = simpleGetIdPConfigBy (^. idpMetadata . edIssuer)

instance SPHandler SimpleError TestSP where
  type NTCTX TestSP = CtxV

  nt :: forall x. CtxV -> TestSP x -> Handler x
  nt = handlerFromTestSP

handlerFromTestSP :: CtxV -> TestSP a -> Handler a
handlerFromTestSP ctx (TestSP m) = Handler . ExceptT . fmap (fmapL toServantErr) . runExceptT $ m `runReaderT` ctx

ioFromTestSP :: CtxV -> TestSP a -> IO a
ioFromTestSP ctx m = either (throwIO . ErrorCall . show) pure =<< (runExceptT . runHandler' $ handlerFromTestSP ctx m)


newtype TestSPStoreIdP a = TestSPStoreIdP { runTestSPStoreIdP :: ExceptT SimpleError (Reader (Maybe IdPConfig_)) a }
  deriving (Functor, Applicative, Monad, MonadReader (Maybe IdPConfig_), MonadError SimpleError)

instance HasConfig TestSPStoreIdP where
  type ConfigExtra TestSPStoreIdP = ()
  getConfig = error "n/a"

instance SPStoreIdP SimpleError TestSPStoreIdP where
  storeIdPConfig = error "n/a"
  getIdPConfig = error "n/a"
  getIdPConfigByIssuer _ = maybe (throwError $ UnknownIdP "<n/a>") pure =<< ask


testAuthRespApp :: IO CtxV -> SpecWith (CtxV, Application) -> Spec
testAuthRespApp = withapp (Proxy @APIAuthResp')
  (authresp' defSPIssuer defResponseURI (HandleVerdictRedirect simpleOnSuccess))

withapp
  :: forall (api :: *). (HasServer api '[])
  => Proxy api -> ServerT api TestSP -> IO CtxV -> SpecWith (CtxV, Application) -> Spec
withapp proxy handler mkctx = with (mkctx <&> \ctx -> (ctx, app ctx))
  where
    app ctx = serve proxy (hoistServer (Proxy @api) (nt @SimpleError @TestSP ctx) handler :: Server api)

runtest :: (CtxV -> WaiSession a) -> ((CtxV, Application) -> IO a)
runtest test (ctx, app) = unWaiSession (test ctx) `runSession` app

runtest' :: WaiSession a -> ((CtxV, Application) -> IO a)
runtest' action = runtest (\_ctx -> action)
