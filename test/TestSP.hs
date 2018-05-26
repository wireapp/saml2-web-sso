{-# LANGUAGE OverloadedStrings #-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module TestSP where

import Control.Exception (throwIO, ErrorCall(..))
import Control.Monad.Except
import Control.Monad.State
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO
import Servant.Server
import Text.XML.DSig
import Text.XML.Util
import Util


data Ctx = Ctx
  { _ctxNow    :: Time
  , _ctxConfig :: Config
  }
  deriving (Eq, Show)

makeLenses ''Ctx

testCtx1 :: Ctx
testCtx1 = Ctx
  { _ctxNow = timeNow
  , _ctxConfig = fallbackConfig & cfgLogLevel .~ SILENT
  }

-- | Use this to see more output on a per-test basis.
verbose :: Ctx -> Ctx
verbose = ctxConfig . cfgLogLevel .~ DEBUG

mkTestCtx2 :: IO Ctx
mkTestCtx2 = mkmyidp <&> \myidp -> testCtx1 & ctxConfig . cfgIdps .~ [myidp]

mkmyidp :: IO IdPConfig
mkmyidp = do
  Right cert <- parseKeyInfo <$> readSampleIO "microsoft-idp-keyinfo.xml"
  pure $ IdPConfig
    "myidp"
    (unsafeParseURI "https://login.microsoftonline.com/682febe8-021b-4fde-ac09-e60085f05181/FederationMetadata/2007-06/FederationMetadata.xml")
    (mkIssuer "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/")
    (unsafeParseURI "http://myidp.io/sso")
    cert

timeLongAgo     :: Time
timeLongAgo     = unsafeReadTime "1918-04-14T09:58:58.457Z"

timeNow         :: Time
timeNow         = unsafeReadTime "2018-03-11T17:13:13Z"

timeIn10minutes :: Time
timeIn10minutes = unsafeReadTime "2018-03-11T17:23:00.01Z"

timeIn20minutes :: Time
timeIn20minutes = unsafeReadTime "2018-03-11T17:33:00Z"


newtype TestSP a = TestSP { runTestSP :: StateT Ctx Handler a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadState Ctx, MonadError ServantErr)

instance HasConfig TestSP where
  getConfig = gets (^. ctxConfig)

instance SP TestSP where
  getNow :: TestSP Time
  getNow = gets (^. ctxNow)

instance SPHandler TestSP where
  type NTCTX TestSP = Ctx

  nt :: forall x. Ctx -> TestSP x -> Handler x
  nt ctx (TestSP m) = m `evalStateT` ctx

testSP :: Ctx -> TestSP a -> IO a
testSP ctx (TestSP m) = either (throwIO . ErrorCall . show) pure =<< runHandler (m `evalStateT` ctx)
