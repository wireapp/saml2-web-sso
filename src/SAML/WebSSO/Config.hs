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

-- TODO: set `-XNoDeriveAnyClass`.
-- TODO: disallow orphans.
module SAML.WebSSO.Config where

import Data.Aeson
import Data.Aeson.TH
import Data.Monoid
import Data.String.Conversions
import GHC.Generics
import Lens.Micro.TH
import System.Environment
import System.FilePath
import System.IO
import Text.XML.DSig
import URI.ByteString

import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml

import SAML.WebSSO.Config.TH (deriveJSONOptions)
import SAML.WebSSO.Types
import Text.XML.Util (unsafeParseURI, parseURI', renderURI)


----------------------------------------------------------------------
-- data types

data Config = Config
  { _cfgVersion           :: Version
  , _cfgLogLevel          :: LogLevel
  , _cfgSPHost            :: String
  , _cfgSPPort            :: Int
  , _cfgSPAppURI          :: URI
  , _cfgSPSsoURI          :: URI
  , _cfgIdps              :: [IdPConfig]
  }
  deriving (Eq, Show, Generic)

data LogLevel = DEBUG | INFO | WARN | ERROR | CRITICAL | SILENT
  deriving (Eq, Ord, Show, Enum, Bounded, Generic, FromJSON, ToJSON)

data IdPConfig = IdPConfig
  { _idpPath            :: ST
  , _idpMetadata        :: URI
  , _idpIssuerID        :: URI
  , _idpRequestUri      :: URI
  , _idpPublicKey       :: X509.SignedCertificate
  }
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- instances

makeLenses ''Config
makeLenses ''IdPConfig

deriveJSON deriveJSONOptions ''Config
deriveJSON deriveJSONOptions ''IdPConfig

instance FromJSON URI where
  parseJSON = (>>= either unerror pure . parseURI') . parseJSON
    where unerror = fail . ("could not parse config: " <>) . show

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


----------------------------------------------------------------------
-- default

fallbackConfig :: Config
fallbackConfig = Config
  { _cfgVersion           = Version_2_0
  , _cfgLogLevel          = DEBUG
  , _cfgSPHost            = "localhost"
  , _cfgSPPort            = 8081
  , _cfgSPAppURI          = unsafeParseURI "https://me.wire.com/sp"
  , _cfgSPSsoURI          = unsafeParseURI "https://me.wire.com/sso"
  , _cfgIdps              = mempty
  }


----------------------------------------------------------------------
-- IO

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
