{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE Strict, StrictData #-}

-- FUTUREWORK: set `-XNoDeriveAnyClass`.
module SAML2.WebSSO.Config where

import Control.Monad (when)
import Data.Aeson
import Data.Maybe (fromMaybe)
import Data.List.NonEmpty
import Data.String.Conversions
import GHC.Generics
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO.Types
import System.Environment
import System.FilePath
import System.IO
import URI.ByteString
import URI.ByteString.QQ

import qualified Data.Yaml as Yaml


----------------------------------------------------------------------
-- data types

type Config_ = Config ()

data Config extra = Config
  { _cfgVersion           :: Version
  , _cfgLogLevel          :: Level
  , _cfgSPHost            :: String
  , _cfgSPPort            :: Int
  , _cfgSPAppURI          :: URI
  , _cfgSPSsoURI          :: URI
  , _cfgContacts          :: NonEmpty ContactPerson
  , _cfgIdps              :: [IdPConfig extra]
  }
  deriving (Eq, Show, Generic)

-- | this looks exactly like tinylog's type, but we redefine it here to avoid the dependency.
data Level = Trace | Debug | Info | Warn | Error | Fatal
  deriving (Eq, Ord, Show, Enum, Bounded, Generic, FromJSON, ToJSON)


----------------------------------------------------------------------
-- instances

makeLenses ''Config

instance ToJSON a => ToJSON (Config a) where
  toJSON Config {..} = object $
    [ "version"    .= _cfgVersion
    , "logLevel"   .= _cfgLogLevel
    , "spHost"     .= _cfgSPHost
    , "spPort"     .= _cfgSPPort
    , "spAppUri"   .= _cfgSPAppURI
    , "spSsoUri"   .= _cfgSPSsoURI
    , "contacts"   .= _cfgContacts
    ] <>
    [ "idps" .= _cfgIdps | not $ Prelude.null _cfgIdps ]

instance FromJSON a => FromJSON (Config a) where
  parseJSON = withObject "Config" $ \obj -> do
    _cfgVersion           <- obj .: "version"
    _cfgLogLevel          <- obj .: "logLevel"
    _cfgSPHost            <- obj .: "spHost"
    _cfgSPPort            <- obj .: "spPort"
    _cfgSPAppURI          <- obj .: "spAppUri"
    _cfgSPSsoURI          <- obj .: "spSsoUri"
    _cfgContacts          <- obj .: "contacts"
    _cfgIdps              <- fromMaybe [] <$> obj .:? "idps"
    pure Config {..}


----------------------------------------------------------------------
-- default

fallbackConfig :: Config extra
fallbackConfig = Config
  { _cfgVersion           = Version_2_0
  , _cfgLogLevel          = Debug
  , _cfgSPHost            = "localhost"
  , _cfgSPPort            = 8081
  , _cfgSPAppURI          = [uri|https://example-sp.com/landing|]
  , _cfgSPSsoURI          = [uri|https://example-sp.com/sso|]
  , _cfgContacts          = fallbackContact :| []
  , _cfgIdps              = mempty
  }

fallbackContact :: ContactPerson
fallbackContact = ContactPerson
  { _cntType      = ContactSupport
  , _cntCompany   = Just "evil corp."
  , _cntGivenName = Just "Dr."
  , _cntSurname   = Just "Girlfriend"
  , _cntEmail     = Just [uri|email:president@evil.corp|]
  , _cntPhone     = Just "+314159265"
  }


----------------------------------------------------------------------
-- IO

configIO :: (FromJSON extra, ToJSON extra) => IO (Config extra)
configIO = readConfig =<< configFilePath

configFilePath :: IO FilePath
configFilePath = (</> "server.yaml") <$> getEnv "SAML2_WEB_SSO_ROOT"

readConfig :: forall extra. (FromJSON extra, ToJSON extra) => FilePath -> IO (Config extra)
readConfig filepath =
  either (\err -> fallbackConfig <$ warn err) (\cnf -> info cnf >> pure cnf)
  =<< Yaml.decodeFileEither filepath
  where
    info :: Config extra -> IO ()
    info cfg = when (cfg ^. cfgLogLevel >= Info) $
      hPutStrLn stderr . cs . Yaml.encode $ cfg

    warn :: Yaml.ParseException -> IO ()
    warn err = hPutStrLn stderr $
      "*** could not read config file: " <> show err <>
      "  using default!  see SAML.WebSSO.Config for details!"

-- | Convenience function to write a config file if you don't already have one.  Writes to
-- `$SAML2_WEB_SSO_ROOT/server.yaml`.  Warns if env does not contain the root.
writeConfig :: ToJSON extra => Config extra -> IO ()
writeConfig cfg = (`Yaml.encodeFile` cfg) =<< configFilePath


----------------------------------------------------------------------
-- class

class (Monad m) => HasConfig m where
  type family ConfigExtra m :: *
  getConfig :: m (Config (ConfigExtra m))
