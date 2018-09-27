module Util.Types where

import Control.Concurrent.MVar
import Data.String.Conversions
import Lens.Micro.TH
import SAML2.WebSSO
import SAML2.WebSSO.API.Example


data Ctx = Ctx
  { _ctxNow            :: Time
  , _ctxConfig         :: Config_
  , _ctxAssertionStore :: MVar AssertionStore
  , _ctxRequestStore   :: MVar RequestStore
  }

instance Show Ctx where
  show (Ctx n c _ _) = "(Ctx " <> show (n, c) <> ")"

makeLenses ''Ctx
