{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE Strict, StrictData #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- TODO: set `-XNoDeriveAnyClass`.
-- TODO: disallow orphans.
module SAML2.WebSSO.Config where

import Control.Monad (when)
import Data.Aeson
import Data.Aeson.TH
import Data.Monoid
import Data.String.Conversions
import GHC.Generics
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO.Config.TH (deriveJSONOptions)
import SAML2.WebSSO.Types
import System.Environment
import System.FilePath
import System.IO
import Text.XML.DSig
import Text.XML.Util (unsafeParseURI, parseURI', renderURI)
import URI.ByteString

import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml


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

data LogLevel = SILENT | CRITICAL | ERROR | WARN | INFO | DEBUG
  deriving (Eq, Ord, Show, Enum, Bounded, Generic, FromJSON, ToJSON)

data IdPConfig = IdPConfig
  { _idpPath            :: ST
  , _idpMetadata        :: URI
  , _idpIssuer          :: Issuer
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
    info cfg = when (cfg ^. cfgLogLevel >= INFO) $
      hPutStrLn stderr . cs . Yaml.encode $ cfg

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
