{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Util.TestSP where

import Control.Concurrent.MVar
import Control.Exception (throwIO, ErrorCall(..))
import Control.Lens
import Control.Monad.Except
import Control.Monad.Reader
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe
import Data.Time
import Data.UUID as UUID
import GHC.Stack
import Network.Wai.Test (runSession)
import SAML2.WebSSO
import SAML2.WebSSO.API.Example (GetAllIdPs(..), simpleStoreID', simpleUnStoreID', simpleIsAliveID', simpleGetIdPConfigBy)
import SAML2.WebSSO.Test.Credentials
import Servant
import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.Internal (unWaiSession)
import URI.ByteString.QQ
import Util.Types

import qualified Data.Map as Map


-- | FUTUREWORK: we already have 'SimpleSP'; is there a good reason why we need both types?
newtype TestSP a = TestSP { runTestSP :: ReaderT CtxV (ExceptT SimpleError IO) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader CtxV, MonadError SimpleError)

instance HasConfig TestSP where
  getConfig = (^. ctxConfig) <$> (liftIO . readMVar =<< ask)

instance HasLogger TestSP
instance HasCreateUUID TestSP
instance HasNow TestSP where
  -- Make TestSP to move forward in time after each look at the clock.
  getNow = modifyCtx (\ctx -> (ctx & ctxNow %~ (1 `addTime`), ctx ^. ctxNow))


-- | These helpers are very similar to the ones in "SAML2.WebSSO.API.Example".  Exercise to the
-- reader: implement only once, use twice.  (Some hints: None of the "lens through IORef/MVar/etc"
-- libraries took off. There's http://hackage.haskell.org/package/monad-var but I haven't looked at
-- it. You might also want to read ekmett's comments at
-- https://www.reddit.com/r/haskell/comments/8gc8p0/extensible_monadic_lenses/. Don't ask me about
-- monadic lenses though, I'm really clueless.)
simpleStoreID
  :: (MonadIO m, MonadReader (MVar ctx) m)
  => Lens' ctx (Map.Map (ID a) Time) -> ID a -> Time -> m ()
simpleStoreID sel item endOfLife = do
  store <- ask
  liftIO $ modifyMVar_ store (pure . (sel %~ simpleStoreID' item endOfLife))

simpleUnStoreID
  :: (MonadIO m, MonadReader (MVar ctx) m)
  => Lens' ctx (Map.Map (ID a) Time) -> ID a -> m ()
simpleUnStoreID sel item = do
  store <- ask
  liftIO $ modifyMVar_ store (pure . (sel %~ simpleUnStoreID' item))

simpleIsAliveID
  :: (MonadIO m, MonadReader (MVar ctx) m, SP m)
  => Lens' ctx (Map.Map (ID a) Time) -> ID a -> m Bool
simpleIsAliveID sel item = do
  now   <- getNow
  store <- ask
  items <- liftIO $ readMVar store
  pure $ simpleIsAliveID' now item (items ^. sel)

instance SPStoreID AuthnRequest TestSP where
  storeID   = simpleStoreID   ctxRequestStore
  unStoreID = simpleUnStoreID ctxRequestStore
  isAliveID = simpleIsAliveID ctxRequestStore

instance SPStoreID Assertion TestSP where
  storeID   = simpleStoreID   ctxAssertionStore
  unStoreID = simpleUnStoreID ctxAssertionStore
  isAliveID = simpleIsAliveID ctxAssertionStore


instance SPStoreIdP SimpleError TestSP where
  type IdPConfigExtra TestSP = ()
  storeIdPConfig _ = pure ()
  getIdPConfig = simpleGetIdPConfigBy readIdPs (^. idpId)
  getIdPConfigByIssuer = simpleGetIdPConfigBy readIdPs (^. idpMetadata . edIssuer)

instance GetAllIdPs SimpleError TestSP where
  getAllIdPs = (^. ctxIdPs) <$> (ask >>= liftIO . readMVar)

instance SPHandler SimpleError TestSP where
  type NTCTX TestSP = CtxV

  nt :: forall x. CtxV -> TestSP x -> Handler x
  nt = handlerFromTestSP

readIdPs :: TestSP [IdPConfig_]
readIdPs = ((^. ctxIdPs) <$> (ask >>= liftIO . readMVar))

handlerFromTestSP :: CtxV -> TestSP a -> Handler a
handlerFromTestSP ctx (TestSP m) = Handler . ExceptT . fmap (fmapL toServantErr) . runExceptT $ m `runReaderT` ctx

ioFromTestSP :: CtxV -> TestSP a -> IO a
ioFromTestSP ctx m = either (throwIO . ErrorCall . show) pure =<< (runExceptT . runHandler' $ handlerFromTestSP ctx m)


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


mkTestCtxSimple :: MonadIO m => m CtxV
mkTestCtxSimple = liftIO $ do
  let _ctxNow            = timeNow  -- constant time value, see below
      _ctxConfig         = fallbackConfig & cfgLogLevel .~ Fatal
      _ctxIdPs           = mempty
      _ctxAssertionStore = mempty
      _ctxRequestStore   = mempty
  newMVar Ctx {..}

mkTestCtxWithIdP :: MonadIO m => m CtxV
mkTestCtxWithIdP = liftIO $ do
  ctxmv <- mkTestCtxSimple
  liftIO $ modifyMVar_ ctxmv (pure . (ctxIdPs .~ [testIdPConfig]))
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

timeInALongTime :: Time
timeInALongTime = unsafeReadTime "2045-04-14T09:58:58.457Z"

timeNow         :: Time
timeNow         = unsafeReadTime "2018-03-11T17:13:13Z"

timeIn5seconds  :: Time
timeIn5seconds  = unsafeReadTime "2018-03-11T17:13:18Z"

timeIn10seconds :: Time
timeIn10seconds = unsafeReadTime "2018-03-11T17:13:23Z"

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

-- | Run an action at a time specified relative to now.  This does NOT support hspec's 'parallel'.
timeTravel :: (HasCallStack, MonadIO m, MonadReader CtxV m) => NominalDiffTime -> m a -> m a
timeTravel distance action = do
  let mv dist_ = modifyCtx_ (ctxNow %~ (dist_ `addTime`))
  mv distance
  result <- action
  mv (-distance)
  pure result
