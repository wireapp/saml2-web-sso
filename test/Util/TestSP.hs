{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Util.TestSP where

import Control.Concurrent.MVar
import Control.Exception (throwIO, ErrorCall(..))
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.State
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe
import Data.UUID as UUID
import Lens.Micro
import SAML2.WebSSO
import SAML2.WebSSO.API.Example
import SAML2.WebSSO.Test.Credentials
import Servant.Server
import URI.ByteString.QQ
import Util.Types


mkTestCtxSimple :: MonadIO m => m Ctx
mkTestCtxSimple = liftIO $ do
  let _ctxNow         = timeNow  -- constant time value, see below
      _ctxConfig      = fallbackConfig & cfgLogLevel .~ Fatal
  _ctxAssertionStore <- newMVar mempty
  _ctxRequestStore   <- newMVar mempty
  pure Ctx {..}

mkTestCtxWithIdP :: MonadIO m => m Ctx
mkTestCtxWithIdP = liftIO $ do
  mkTestCtxSimple <&> ctxConfig . cfgIdps .~ [testIdPConfig]

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


newtype TestSP a = TestSP { runTestSP :: StateT Ctx (ExceptT SimpleError IO) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState Ctx, MonadError SimpleError)

instance HasConfig TestSP where
  type ConfigExtra TestSP = ()
  getConfig = gets (^. ctxConfig)

instance SP TestSP where
  -- Make TestSP to move forward in time with each look at the clock.
  getNow = state (\s -> (s ^. ctxNow, s & ctxNow %~ (1 `addTime`)))

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
  getIdPConfigByIssuer = simpleGetIdPConfigBy (^. idpMetadata . edIssuer)

instance SPHandler SimpleError TestSP where
  type NTCTX TestSP = Ctx

  nt :: forall x. Ctx -> TestSP x -> Handler x
  nt = handlerFromTestSP

handlerFromTestSP :: Ctx -> TestSP a -> Handler a
handlerFromTestSP ctx (TestSP m) = Handler . ExceptT . fmap (fmapL toServantErr) . runExceptT $ m `evalStateT` ctx

ioFromTestSP :: Ctx -> TestSP a -> IO a
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
