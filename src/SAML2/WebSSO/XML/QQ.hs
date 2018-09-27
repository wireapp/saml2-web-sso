{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module SAML2.WebSSO.XML.QQ where

import Control.Category (Category(..))
import Control.Lens hiding (element)
import Control.Monad
import Data.String.Conversions
import GHC.Stack
import Prelude hiding ((.), id)
import SAML2.Util
import SAML2.WebSSO.Types
import Text.Hamlet.XML
import Text.XML
import Text.XML.DSig (renderKeyInfo)

import qualified Data.List.NonEmpty as NL


renderIdPMetadata :: HasCallStack => IdPMetadata -> Element
renderIdPMetadata (IdPMetadata issuer requri (NL.toList -> certs)) = nodesToElem $ repairNamespaces nodes
  where
    nodes = [xml|
      <EntityDescriptor
        ID="#{descID}"
        entityID="#{entityID}"
        xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
              <KeyDescriptor use="signing">
                  ^{certNodes}
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{authnUrl}">
      |]

    descID = "_0c29ba62-a541-11e8-8042-873ef87bdcba"
    entityID = renderURI $ issuer ^. fromIssuer
    authnUrl = renderURI $ requri
    certNodes = mconcat $ mkCertNode <$> certs

    mkCertNode
      = either (error . show) id
      . fmap docToNodes
      . parseLBS def
      . cs
      . renderKeyInfo
