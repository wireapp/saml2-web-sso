{-# LANGUAGE TemplateHaskell    #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE OverloadedStrings  #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- TODO: make 'config' more pure.
-- TODO: set `-XNoDeriveAnyClass`.
-- TODO: disallow orphans.
module SAML.WebSSO.Config where

import Data.Aeson
import Data.Monoid
import GHC.Generics
import Lens.Micro.TH
import System.Environment
import System.FilePath
import System.IO
import System.IO.Unsafe (unsafePerformIO)
import URI.ByteString

import qualified Data.Yaml as Yaml

import SAML.WebSSO.Types
import SAML.WebSSO.XML (parseURI', renderURI)


data Config = Config
  { _cfgSPURI   :: URI
  , _cfgIdPURI  :: URI
  , _cfgVersion :: Version
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

makeLenses ''Config

fallbackConfig :: Config
fallbackConfig = Config
  { _cfgSPURI   = either (error . show) id $ parseURI' "http://me.wire.com/"
  , _cfgIdPURI  = either (error . show) id $ parseURI' "https://idptestbed/"
  , _cfgVersion = Version_2_0
  }

{-# NOINLINE config #-}
config :: Config
config = unsafePerformIO $ readConfig =<< configFilePath

configFilePath :: IO FilePath
configFilePath = (</> "server.yaml") <$> getEnv "SAML2_WEB_SSO_ROOT"

readConfig :: FilePath -> IO Config
readConfig filepath = either (\err -> fallbackConfig <$ warn err) pure =<< Yaml.decodeFileEither filepath
  where
    warn :: Yaml.ParseException -> IO ()
    warn err = hPutStrLn stderr $ "*** could not read config file: " <> show err <> "  using default!  see SAML.WebSSO.Config for details!"

-- | Convenience function to write a config file if you don't already have one.  Writes to
-- `$SAML2_WEB_SSO_ROOT/server.yaml`.  Warns if env does not contain the root.
writeConfig :: Config -> IO ()
writeConfig cfg = (`Yaml.encodeFile` cfg) =<< configFilePath
