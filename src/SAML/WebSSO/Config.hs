{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE Strict, StrictData #-}
{-# LANGUAGE TemplateHaskell    #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- TODO: make 'config' more pure.
-- TODO: set `-XNoDeriveAnyClass`.
-- TODO: disallow orphans.
module SAML.WebSSO.Config where

import Data.Aeson
import Data.Maybe (fromJust)
import Data.Monoid
import Data.String.Conversions
import GHC.Generics
import GHC.Stack
import Lens.Micro
import Lens.Micro.TH
import System.Environment
import System.FilePath
import System.IO
import Text.XML.DSig
import URI.ByteString

import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml

import SAML.WebSSO.Types
import SAML.WebSSO.XML (parseURI', renderURI)


data Config = Config
  { _cfgVersion           :: Version
  , _cfgSPHost            :: String
  , _cfgSPPort            :: Int
  , _cfgSPAppURI          :: URI
  , _cfgSPSsoURI          :: URI
  , _cfgIdPs              :: [IdPConfig]
  }
  deriving (Eq, Show, Generic, FromJSON, ToJSON)

data IdPConfig = IdPConfig
  { _idpPath            :: ST
  , _idpRequestUrl      :: URI
  , _idpPublicKey       :: X509.SignedCertificate
  }
  deriving (Eq, Show, Generic, FromJSON, ToJSON)

instance FromJSON URI where
  parseJSON = fmap (either unerror id . parseURI') . parseJSON
    where unerror = error . ("could not parse config: " <>) . show

instance ToJSON URI where
  toJSON = toJSON . renderURI

instance FromJSON Version where
  parseJSON (String "SAML2.0") = pure Version_2_0
  parseJSON bad = fail $ "could not parse config: bad version string: " <> show bad

instance ToJSON Version where
  toJSON Version_2_0 = String "SAML2.0"

instance FromJSON X509.SignedCertificate where
  parseJSON = withText "KeyInfo element" $ either fail pure . parseKeyInfo . cs

instance ToJSON X509.SignedCertificate where
  toJSON = String . cs . renderKeyInfo

makeLenses ''Config
makeLenses ''IdPConfig

fallbackConfig :: Config
fallbackConfig = Config
  { _cfgVersion           = Version_2_0
  , _cfgSPHost            = "localhost"
  , _cfgSPPort            = 8081
  , _cfgSPAppURI          = either (error . show) id $ parseURI' "https://me.wire.com/sp"
  , _cfgSPSsoURI          = either (error . show) id $ parseURI' "https://me.wire.com/sso"
  , _cfgIdPs              = mempty
  }

configIO :: IO Config
configIO = readConfig =<< configFilePath

configFilePath :: IO FilePath
configFilePath = (</> "server.yaml") <$> getEnv "SAML2_WEB_SSO_ROOT"

readConfig :: FilePath -> IO Config
readConfig filepath =
  either (\err -> fallbackConfig <$ warn err) (\cnf -> info cnf >> pure cnf)
  =<< Yaml.decodeFileEither filepath
  where
    info :: Config -> IO ()
    info = hPutStrLn stderr . cs . Yaml.encode

    warn :: Yaml.ParseException -> IO ()
    warn err = hPutStrLn stderr $
      "*** could not read config file: " <> show err <>
      "  using default!  see SAML.WebSSO.Config for details!"

-- | Convenience function to write a config file if you don't already have one.  Writes to
-- `$SAML2_WEB_SSO_ROOT/server.yaml`.  Warns if env does not contain the root.
writeConfig :: Config -> IO ()
writeConfig cfg = (`Yaml.encodeFile` cfg) =<< configFilePath


----------------------------------------------------------------------
-- class

class Monad m => HasConfig m where
  getConfig :: m Config

instance HasConfig IO where
  getConfig = configIO


----------------------------------------------------------------------
-- uri paths

data Path = SpPathHome | SpPathLocalLogout | SpPathSingleLogout
          | SsoPathMeta | SsoPathAuthnReq | SsoPathAuthnResp
  deriving (Eq, Show)


getPath :: (HasConfig m, HasCallStack) => Path -> m URI
getPath = fmap (fromJust . parseURI') . getPath'

getPath' :: (HasConfig m, ConvertibleStrings SBS s) => Path -> m s
getPath' = \case
  SpPathHome         -> sp  ""
  SpPathLocalLogout  -> sp  "/logout/local"
  SpPathSingleLogout -> sp  "/logout/single"
  SsoPathMeta        -> sso "/meta"
  SsoPathAuthnReq    -> sso "/authreq"
  SsoPathAuthnResp   -> sso "/authresp"
  where
    sp  p = appendpath p . (^. cfgSPAppURI) <$> getConfig
    sso p = appendpath p . (^. cfgSPSsoURI) <$> getConfig
    appendpath path uri = norm uri { uriPath = uriPath uri <> path }
    norm = cs . normalizeURIRef' httpNormalization
