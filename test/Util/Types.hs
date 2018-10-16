module Util.Types where

import Control.Concurrent.MVar
import Lens.Micro.TH
import SAML2.WebSSO
import SAML2.WebSSO.API.Example


type CtxV = MVar Ctx

data Ctx = Ctx
  { _ctxNow            :: Time
  , _ctxConfig         :: Config
  , _ctxIdPs           :: [IdPConfig_]
  , _ctxAssertionStore :: AssertionStore
  , _ctxRequestStore   :: RequestStore
  }
  deriving (Eq, Show)

makeLenses ''Ctx
