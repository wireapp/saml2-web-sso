{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE Strict, StrictData #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- FUTUREWORK: set `-XNoDeriveAnyClass`.
-- FUTUREWORK: disallow orphans.
module SAML2.WebSSO.Config where

import Control.Monad (when)
import Data.Aeson
import Data.Aeson.TH
import Data.Maybe (fromMaybe)
import Data.Monoid
import Data.List.NonEmpty
import Data.String.Conversions
import GHC.Generics
import Data.UUID as UUID
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO.Config.TH (deriveJSONOptions)
import SAML2.WebSSO.Types
import System.Environment
import System.FilePath
import System.IO
import Text.XML.DSig
import Text.XML.Util (parseURI', renderURI)
import URI.ByteString
import URI.ByteString.QQ

import qualified Data.X509 as X509
import qualified Data.Yaml as Yaml
import qualified Servant


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

newtype IdPId = IdPId { fromIdPId :: UUID } deriving (Eq, Show, Generic, Ord)

type IdPConfig_ = IdPConfig ()

data IdPConfig extra = IdPConfig
  { _idpId              :: IdPId
  , _idpMetadata        :: URI
  , _idpIssuer          :: Issuer
  , _idpRequestUri      :: URI
  , _idpPublicKey       :: X509.SignedCertificate
  , _idpExtraInfo       :: extra
  }
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- instances

idPIdToST :: IdPId -> ST
idPIdToST = UUID.toText . fromIdPId

instance Servant.FromHttpApiData IdPId where
    parseUrlPiece piece = case UUID.fromText piece of
      Nothing -> Left . cs $ "no valid UUID-piece " ++ show piece
      Just uid -> return $ IdPId uid

makeLenses ''Config
makeLenses ''IdPConfig

instance ToJSON a => ToJSON (Config a) where
  toJSON Config {..} = object $
    [ "version"    .= _cfgVersion
    , "log_level"  .= _cfgLogLevel
    , "sp_host"    .= _cfgSPHost
    , "sp_port"    .= _cfgSPPort
    , "sp_app_uri" .= _cfgSPAppURI
    , "sp_sso_uri" .= _cfgSPSsoURI
    , "contacts"   .= _cfgContacts
    ] <>
    [ "idps" .= _cfgIdps | not $ Prelude.null _cfgIdps ]

instance FromJSON a => FromJSON (Config a) where
  parseJSON = withObject "Config" $ \obj -> do
    _cfgVersion           <- obj .: "version"
    _cfgLogLevel          <- obj .: "log_level"
    _cfgSPHost            <- obj .: "sp_host"
    _cfgSPPort            <- obj .: "sp_port"
    _cfgSPAppURI          <- obj .: "sp_app_uri"
    _cfgSPSsoURI          <- obj .: "sp_sso_uri"
    _cfgContacts          <- obj .: "contacts"
    _cfgIdps              <- fromMaybe [] <$> obj .:? "idps"
    pure Config {..}


deriveJSON deriveJSONOptions ''IdPConfig
deriveJSON deriveJSONOptions ''ContactPerson
deriveJSON deriveJSONOptions ''ContactType

instance FromJSON IdPId where
  parseJSON value = (>>= maybe unerror (pure . IdPId) . UUID.fromText) . parseJSON $ value
    where unerror = fail ("could not parse config: " <> (show value))

instance ToJSON IdPId where
  toJSON = toJSON . UUID.toText . fromIdPId

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

fallbackConfig :: Config extra
fallbackConfig = Config
  { _cfgVersion           = Version_2_0
  , _cfgLogLevel          = Debug
  , _cfgSPHost            = "localhost"
  , _cfgSPPort            = 8081
  , _cfgSPAppURI          = [uri|https://me.wire.com/sp|]
  , _cfgSPSsoURI          = [uri|https://me.wire.com/sso|]
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
