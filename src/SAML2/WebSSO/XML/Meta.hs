{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module SAML2.WebSSO.XML.Meta
  ( spID
  , spValidUntil
  , spCacheDuration
  , spOrgName
  , spOrgDisplayName
  , spOrgURL
  , spResponseURL
  , mkSPMetadata
  , parseIdPMetadata
  , renderIdPMetadata
  ) where

import Control.Lens hiding (element)
import Control.Monad.Except
import Data.List.NonEmpty as NL
import Data.Maybe
import Data.Proxy
import Data.String.Conversions
import GHC.Stack
import SAML2.Util
import SAML2.WebSSO.SP
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Text.Hamlet.XML
import Text.XML
import Text.XML.Cursor
import Text.XML.DSig (parseKeyInfo, renderKeyInfo)
import URI.ByteString

import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified Network.URI as OldURI
import qualified SAML2.Bindings.Identifiers as HS
import qualified SAML2.Core.Identifiers as HS
import qualified SAML2.Core.Namespaces as HS
import qualified SAML2.Core.Versioning as HS
import qualified SAML2.Metadata.Metadata as HS
import qualified SAML2.XML as HX
import qualified SAML2.XML.Schema.Datatypes as HX (Duration, UnsignedShort, Boolean)
import qualified SAML2.XML.Signature.Types as HX (Signature)


instance HasXML SPMetadata where
  parse = (importSPMetadata =<<) . either throwError pure . HX.xmlToSAML . renderLBS def . nodesToDoc

instance HasXMLRoot SPMetadata where
  renderRoot = unwrap . parseLBS def . HX.samlToXML . exportSPMetadata
    where
      unwrap = \case
        Right (Document _ el _) -> el
        bad -> error $ "HasXMLRoot SPMetadata: internal error: " <> show bad


-- | Construct SP metadata with a new UUID and current time stamp.
--
-- The @resp@ argument here must match the @finalize-login@ end-point (as can be constructed by
-- 'getSsoURL').
mkSPMetadata :: SP m => ST -> URI -> URI -> NonEmpty ContactPerson -> m SPMetadata
mkSPMetadata nick org resp contact = do
  mid <- createID
  now <- getNow
  pure $ mkSPMetadata' mid now nick org resp contact

mkSPMetadata' :: ID SPMetadata -> Time -> ST -> URI -> URI -> NonEmpty ContactPerson -> SPMetadata
mkSPMetadata' mid now nick org resp contact =
  let _spID             = mid
      _spCacheDuration  = months 1
      _spOrgName        = nick
      _spOrgDisplayName = nick
      _spOrgURL         = org
      _spResponseURL    = resp
      _spContacts       = contact

      years  n = days n * 365
      months n = days n * 30
      days   n = n * 60 * 60 * 24

      Time _spValidUntil = addTime (years 1) now
  in SPMetadata {..}


-- | NB: this works best under the assumption that the input has been constructed by
-- 'exportSPMetadata'.
importSPMetadata :: (HasCallStack, MonadError String m) => HS.Metadata -> m SPMetadata
importSPMetadata (NL.head . HS.descriptors . HS.entityDescriptors -> desc) = do
  case desc of
    HS.SPSSODescriptor {} -> pure ()
    bad -> throwError $ "malformed HS.Descriptor: " <> show bad

  _spID
    <- let raw = HS.roleDescriptorID . HS.descriptorRole $ desc
       in maybe (throwError ("malformed descriptorID: " <> show raw)) (pure . ID . cs) raw
  _spValidUntil
    <- let raw = HS.roleDescriptorValidUntil . HS.descriptorRole $ desc
       in maybe (throwError $ "bad validUntil: " <> show raw) (fmap fromTime . importTime) raw
  _spCacheDuration
    <- let raw = HS.roleDescriptorCacheDuration . HS.descriptorRole $ desc
       in maybe (throwError $ "bad cacheDuration: " <> show raw) pure raw
  _spOrgName :: ST
    <- let raw = case fmap HS.organizationName . HS.roleDescriptorOrganization . HS.descriptorRole $ desc of
             Just (HS.Localized "EN" x :| []) -> Just x
             _ -> Nothing
       in maybe (throwError $ "bad orgName: " <> show raw) (pure . cs) raw
  _spOrgDisplayName :: ST
    <- let raw = case fmap HS.organizationDisplayName . HS.roleDescriptorOrganization . HS.descriptorRole $ desc of
             Just (HS.Localized "EN" x :| []) -> Just x
             _ -> Nothing
       in maybe (throwError $ "bad orgDisplayName: " <> show raw) (pure . cs) raw
  _spOrgURL <- let raw = fmap HS.organizationURL . HS.roleDescriptorOrganization . HS.descriptorRole $ desc
               in case raw of
                    Just (HS.Localized "EN" u :| []) -> pure $ importURL u
                    bad -> throwError $ "bad or no organizationURL" <> show bad
  let _spResponseURL = importURL . HS.endpointLocation . HS.indexedEndpoint . NL.head
                       . HS.descriptorAssertionConsumerService $ desc
  _spContacts <- fmap NL.fromList . mapM importContactPerson . HS.roleDescriptorContactPerson . HS.descriptorRole $ desc
  pure SPMetadata {..}


exportSPMetadata :: HasCallStack => SPMetadata -> HS.Metadata
exportSPMetadata spdesc = HS.EntityDescriptor
    { HS.entityID                        = exportURL (spdesc ^. spOrgURL) :: HS.EntityID
    , HS.metadataID                      = Nothing :: Maybe HX.ID
    , HS.metadataValidUntil              = Nothing :: Maybe HX.DateTime
    , HS.metadataCacheDuration           = Nothing :: Maybe HX.Duration
    , HS.entityAttrs                     = mempty  :: HX.Nodes
    , HS.metadataSignature               = Nothing :: Maybe HX.Signature
    , HS.metadataExtensions              = mempty  :: HS.Extensions
    , HS.entityDescriptors               = HS.Descriptors (exportSPMetadata' spdesc :| [])
    , HS.entityOrganization              = Nothing :: Maybe HS.Organization
    , HS.entityContactPerson             = mempty  :: [HS.Contact]
    , HS.entityAditionalMetadataLocation = mempty  :: [HS.AdditionalMetadataLocation]
    }

-- | [4/2.6], [4/2]
exportSPMetadata' :: HasCallStack => SPMetadata -> HS.Descriptor
exportSPMetadata' spdesc = HS.SPSSODescriptor
    { HS.descriptorRole = HS.RoleDescriptor
      { HS.roleDescriptorID = Just (cs . renderID $ spdesc ^. spID) :: Maybe HX.ID
      , HS.roleDescriptorValidUntil = Just (spdesc ^. spValidUntil) :: Maybe HX.DateTime
      , HS.roleDescriptorCacheDuration = Just (spdesc ^. spCacheDuration) :: Maybe HX.Duration
      , HS.roleDescriptorProtocolSupportEnumeration = [HS.samlURN HS.SAML20 ["protocol"]] :: [HX.AnyURI]
      , HS.roleDescriptorErrorURL = Nothing :: Maybe HX.AnyURI
      , HS.roleDescriptorAttrs = [] :: HX.Nodes
      , HS.roleDescriptorSignature = Nothing :: Maybe HX.Signature
      , HS.roleDescriptorExtensions = HS.Extensions []
      , HS.roleDescriptorKeyDescriptor = [] :: [HS.KeyDescriptor]
      , HS.roleDescriptorOrganization = Just HS.Organization
        { HS.organizationAttrs = []
        , HS.organizationExtensions = HS.Extensions []
        , HS.organizationName = HS.Localized "EN" (cs $ spdesc ^. spOrgName) :| []
        , HS.organizationDisplayName = HS.Localized "EN" (cs $ spdesc ^. spOrgDisplayName) :| []
        , HS.organizationURL = HS.Localized "EN" (exportURL $ spdesc ^. spOrgURL) :| [] :: HX.List1 HS.LocalizedURI
        }
      , HS.roleDescriptorContactPerson = exportContactPerson <$> toList (spdesc ^. spContacts)
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
        , HS.endpointLocation = exportURL $ spdesc ^. spResponseURL :: HX.AnyURI
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


exportURL :: URI -> HX.URI
exportURL = fromJust . OldURI.parseURI . cs . renderURI

importURL :: HX.URI -> URI
importURL = unsafeParseURI . cs . show


exportContactPerson :: ContactPerson -> HS.Contact
exportContactPerson contact = HS.ContactPerson
  { HS.contactType = exportContactType $ contact ^. cntType
  , HS.contactAttrs = []
  , HS.contactExtensions = HS.Extensions []
  , HS.contactCompany = cs <$> contact ^. cntCompany
  , HS.contactGivenName = cs <$> contact ^. cntGivenName
  , HS.contactSurName = cs <$> contact ^. cntSurname
  , HS.contactEmailAddress = maybeToList $ exportURL <$> contact ^. cntEmail :: [HX.AnyURI]
  , HS.contactTelephoneNumber = maybeToList $ cs <$> contact ^. cntPhone
  }

importContactPerson :: MonadError String m => HS.Contact -> m ContactPerson
importContactPerson contact = do
  let _cntType      = importContactType $ HS.contactType contact
      _cntCompany   = cs <$> HS.contactCompany contact
      _cntGivenName = cs <$> HS.contactGivenName contact
      _cntSurname   = cs <$> HS.contactSurName contact
      _cntEmail     = listToMaybe $ importURL <$> HS.contactEmailAddress contact
      _cntPhone     = listToMaybe $ cs <$> HS.contactTelephoneNumber contact
  pure ContactPerson {..}


exportContactType :: ContactType -> HS.ContactType
exportContactType = \case
  ContactTechnical      -> HS.ContactTypeTechnical
  ContactSupport        -> HS.ContactTypeSupport
  ContactAdministrative -> HS.ContactTypeAdministrative
  ContactBilling        -> HS.ContactTypeBilling
  ContactOther          -> HS.ContactTypeOther

importContactType :: HS.ContactType -> ContactType
importContactType = \case
  HS.ContactTypeTechnical      -> ContactTechnical
  HS.ContactTypeSupport        -> ContactSupport
  HS.ContactTypeAdministrative -> ContactAdministrative
  HS.ContactTypeBilling        -> ContactBilling
  HS.ContactTypeOther          -> ContactOther


instance HasXML IdPMetadata where
  parse [NodeElement el] = parseIdPMetadata el
  parse bad = die (Proxy @IdPMetadata) bad

instance HasXMLRoot IdPMetadata where
  renderRoot = renderIdPMetadata


parseIdPMetadata :: MonadError String m => Element -> m IdPMetadata
parseIdPMetadata el@(Element _ attrs _) = do
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
      bad         -> throwError $ "unexpected request uri: " <> show (target, bad)

  let cursorToKeyInfo :: MonadError String m => Cursor -> m X509.SignedCertificate
      cursorToKeyInfo = \case
        (node -> NodeElement key) -> parseKeyInfo . renderText def . mkDocument $ key
        bad -> throwError $ "unexpected: could not parse x509 cert: " <> show bad

  -- some metadata documents really have more than one of these.  since there is no way of knowing
  -- which one is correct, we accept all of them.
  _edCertAuthnResponse :: NonEmpty X509.SignedCertificate <- do
    let cur = fromNode $ NodeElement el
        target :: [Cursor]
        target = cur $// element "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
                     &/  element "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor"
                     >=> attributeIs "use" "signing"
                     &/  element "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    (cursorToKeyInfo `mapM` target) >>= \case
      [] -> throwError $ "could not find any AuthnResponse signature certificates."
      (x:xs) -> pure $ x :| xs

  pure IdPMetadata {..}


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
