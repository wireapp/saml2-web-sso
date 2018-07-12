{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module SAML2.WebSSO.XML.Meta
  ( spdID
  , spdValidUntil
  , spdCacheDuration
  , spdOrgName
  , spdOrgDisplayName
  , spdOrgURL
  , spdResponseURL

  , spDesc
  , spMeta

  , parseIdPDesc
  ) where

import Control.Monad.Except
import Data.List.NonEmpty
import Data.Maybe
import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import Lens.Micro
import SAML2.WebSSO.SP
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Text.XML
import Text.XML.Cursor
import Text.XML.DSig (parseKeyInfo)
import Text.XML.Util
import URI.ByteString

import qualified Data.Map as Map
import qualified Data.UUID as UUID
import qualified Data.X509 as X509
import qualified Network.URI as OldURI
import qualified SAML2.Bindings.Identifiers as HS
import qualified SAML2.Core.Datatypes as HS hiding (AnyURI)
import qualified SAML2.Core.Identifiers as HS
import qualified SAML2.Core.Namespaces as HS
import qualified SAML2.Core.Versioning as HS
import qualified SAML2.Metadata.Metadata as HS
import qualified SAML2.XML as HX hiding (AnyURI)
import qualified SAML2.XML.Schema.Datatypes as HX
import qualified SAML2.XML.Signature.Types as HX


instance HasXML SPDesc where
  parse [NodeElement el] = pure . SPDesc $ Document defPrologue el defMiscellaneous
  parse bad = die (Proxy @SPDesc) bad

instance HasXMLRoot SPDesc where
  renderRoot (SPDesc (Document _ el _)) = el


spDesc :: SP m => ST -> URI -> URI -> NonEmpty ContactPerson -> m SPDescPre
spDesc nick org resp contact = createUUID >>= \uuid -> spDesc' uuid nick org resp contact

spDesc' :: SP m => UUID.UUID -> ST -> URI -> URI -> NonEmpty ContactPerson -> m SPDescPre
spDesc' uuid nick org resp contact = do
  let _spdID             = uuid
      _spdCacheDuration  = months 1
      _spdOrgName        = nick
      _spdOrgDisplayName = nick
      _spdOrgURL         = org
      _spdResponseURL    = resp
      _spdContacts       = contact

      years  n = days n * 365
      months n = days n * 30
      days   n = n * 60 * 60 * 24

  Time _spdValidUntil <- addTime (years 1) <$> getNow
  pure SPDescPre {..}


-- | FUTUREWORK: this can throw async errors!  this shouldn't be necessary!
spMeta :: HasCallStack => SPDescPre -> SPDesc
spMeta spdesc = either (error . show) SPDesc . parseLBS def . HX.samlToXML $ spMeta' spdesc

-- | [4/2.6], [4/2]
spMeta' :: HasCallStack => SPDescPre -> HS.Descriptor
spMeta' spdesc = HS.SPSSODescriptor
    { HS.descriptorRole = HS.RoleDescriptor
      { HS.roleDescriptorID = Just (UUID.toString $ spdesc ^. spdID) :: Maybe HS.ID
      , HS.roleDescriptorValidUntil = Just (spdesc ^. spdValidUntil) :: Maybe HS.DateTime
      , HS.roleDescriptorCacheDuration = Just (spdesc ^. spdCacheDuration) :: Maybe HX.Duration
      , HS.roleDescriptorProtocolSupportEnumeration = [HS.samlURN HS.SAML20 ["protocol"]] :: [HX.AnyURI]
      , HS.roleDescriptorErrorURL = Nothing :: Maybe HX.AnyURI
      , HS.roleDescriptorAttrs = [] :: HX.Nodes
      , HS.roleDescriptorSignature = Nothing :: Maybe HX.Signature
      , HS.roleDescriptorExtensions = HS.Extensions []
      , HS.roleDescriptorKeyDescriptor = [] :: [HS.KeyDescriptor]
      , HS.roleDescriptorOrganization = Just HS.Organization
        { HS.organizationAttrs = []
        , HS.organizationExtensions = HS.Extensions []
        , HS.organizationName = HS.Localized "EN" (cs $ spdesc ^. spdOrgName) :| []
        , HS.organizationDisplayName = HS.Localized "EN" (cs $ spdesc ^. spdOrgDisplayName) :| []
        , HS.organizationURL = HS.Localized "EN" (castURL $ spdesc ^. spdOrgURL) :| [] :: HX.List1 HS.LocalizedURI
        }
      , HS.roleDescriptorContactPerson = toList (spdesc ^. spdContacts) <&> \contact ->
          HS.ContactPerson
            { HS.contactType = castContactType $ contact ^. cntType
            , HS.contactAttrs = []
            , HS.contactExtensions = HS.Extensions []
            , HS.contactCompany = cs <$> contact ^. cntCompany
            , HS.contactGivenName = cs <$> contact ^. cntGivenName
            , HS.contactSurName = cs <$> contact ^. cntSurname
            , HS.contactEmailAddress = maybeToList $ castURL <$> contact ^. cntEmail :: [HX.AnyURI]
            , HS.contactTelephoneNumber = maybeToList $ cs <$> contact ^. cntPhone
            }
      }
    , HS.descriptorSSO = HS.SSODescriptor
      { HS.ssoDescriptorArtifactResolutionService = [] :: [HS.IndexedEndpoint]
      , HS.ssoDescriptorSingleLogoutService = [] :: [HS.Endpoint]
      , HS.ssoDescriptorManageNameIDService = [] :: [HS.Endpoint]
      , HS.ssoDescriptorNameIDFormat = [HX.Identified HS.NameIDFormatUnspecified, HX.Identified HS.NameIDFormatEntity]  -- [1/8.3]
      }
    , HS.descriptorAuthnRequestsSigned = False
    , HS.descriptorWantAssertionsSigned = True
    , HS.descriptorAssertionConsumerService = HS.IndexedEndpoint
      { HS.indexedEndpoint = HS.Endpoint
        { HS.endpointBinding = HX.Identified HS.BindingHTTPPOST :: HX.IdentifiedURI HS.Binding
        , HS.endpointLocation = castURL $ spdesc ^. spdResponseURL :: HX.AnyURI
        , HS.endpointResponseLocation = Nothing :: Maybe HX.AnyURI
        , HS.endpointAttrs = [] :: HX.Nodes
        , HS.endpointXML = [] :: HX.Nodes
        }
      , HS.indexedEndpointIndex = 0 :: HX.UnsignedShort
      , HS.indexedEndpointIsDefault = True :: HX.Boolean
      } :| [] :: HX.List1 HS.IndexedEndpoint
    , HS.descriptorAttributeConsumingService = [] :: [HS.AttributeConsumingService]
      -- (for identification we do not need any attributes, but can use the 'SubjectID' that is
      -- always included in the response.)
    }


castURL :: URI -> HX.URI
castURL = fromJust . OldURI.parseURI . cs . renderURI

castContactType :: ContactType -> HS.ContactType
castContactType = \case
  ContactTechnical      -> HS.ContactTypeTechnical
  ContactSupport        -> HS.ContactTypeSupport
  ContactAdministrative -> HS.ContactTypeAdministrative
  ContactBilling        -> HS.ContactTypeBilling
  ContactOther          -> HS.ContactTypeOther


instance HasXML IdPDesc where
  parse [NodeElement el] = parseIdPDesc el
  parse bad = die (Proxy @IdPDesc) bad

instance HasXMLRoot IdPDesc where
  renderRoot _ = error "instance HasXMLRoot SPDesc: not implemented."


parseIdPDesc :: MonadError String m => Element -> m IdPDesc
parseIdPDesc el@(Element _ attrs _) = do
  _edIssuer :: Issuer <- do
    issueruri :: ST <- maybe (throwError "no issuer") pure (Map.lookup "entityID" attrs)
    Issuer <$> parseURI' issueruri

  _edRequestURI :: URI <- do
    let cur = fromNode $ NodeElement el
        target :: [ST]
        target = cur $// element "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
                     &/  element "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"
                     >=> attributeIs "Binding" "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                     >=> attribute "Location"

    case parseURI' <$> target of
      [Right uri] -> pure uri
      [Left msg]  -> throwError $ "bad request uri: " <> msg
      _bad        -> throwError $ "no request uri"

  _edPublicKeys :: [X509.SignedCertificate] <- do
    let cur = fromNode $ NodeElement el
        target :: [Cursor]
        target = cur $// element "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
                     &/  element "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor"
                     >=> attributeIs "use" "signing"
                     &/  element "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
          -- TODO: is the public key for metadata verification located elsewhere in the metadata?
    forM target $ \case
      (node -> NodeElement key) -> parseKeyInfo . renderText def . mkDocument $ key
      bad -> throwError $ "unexpected: could not parse x509 cert: " <> show bad

  pure IdPDesc {..}
