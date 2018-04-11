{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE OverloadedStrings     #-}

module SAML.WebSSO.Config where

import Lens.Micro.TH
import SAML.WebSSO.Types
import SAML.WebSSO.XML (parseURI')
import URI.ByteString


data Config = Config
  { _cfgSPURI   :: URI
  , _cfgIdPURI  :: URI
  , _cfgVersion :: Version
  }

makeLenses ''Config

config :: Config
config = Config
  { _cfgSPURI   = either (error . show) id $ parseURI' "http://me.wire.com/"
  , _cfgIdPURI  = either (error . show) id $ parseURI' "https://idptestbed/"
  , _cfgVersion = Version_2_0
  }
