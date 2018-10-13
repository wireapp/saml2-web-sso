{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}

module SAML2.WebSSO.Servant.CPP where

import qualified Servant

type MkLink endpoint = Servant.MkLink endpoint
#if MIN_VERSION_servant(0,14,0)
                       Link
#endif
