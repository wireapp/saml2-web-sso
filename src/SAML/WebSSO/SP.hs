{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DefaultSignatures     #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module SAML.WebSSO.SP where

import Control.Monad.IO.Class
import Data.Time
import Data.UUID as UUID
import Data.UUID.V4 as UUID
import Lens.Micro
import SAML.WebSSO.Types
import SAML.WebSSO.Config
import URI.ByteString
import Servant.Server


class Monad m => SP m where
  nt :: (forall x. m x -> Handler x)
  default nt :: m ~ Handler => (forall x. m x -> Handler x)
  nt = id

  logger :: String -> m ()
  default logger :: MonadIO m => String -> m ()
  logger = liftIO . putStrLn

  createUUID :: m UUID
  default createUUID :: MonadIO m => m UUID
  createUUID = liftIO UUID.nextRandom

  getNow :: m Time
  default getNow :: MonadIO m => m Time
  getNow = Time <$> liftIO getCurrentTime

instance SP Handler


createID :: SP m => m ID
createID = ID . UUID.toText <$> createUUID

createAuthnRequest :: SP m => m AuthnRequest
createAuthnRequest = do
  x0 <- createID
  let x1 = config ^. cfgVersion
  x2 <- getNow
  let x3 = config ^. cfgSPURI

  pure AuthnRequest
    { _rqID               = x0 :: ID
    , _rqVersion          = x1 :: Version
    , _rqIssueInstant     = x2 :: Time
    , _rqIssuer           = x3 :: URI
    , _rqDestination      = Nothing
    }


getIdPMeta :: SP m => m ()
getIdPMeta = undefined

getUser :: SP m => String -> m ()
getUser = undefined
