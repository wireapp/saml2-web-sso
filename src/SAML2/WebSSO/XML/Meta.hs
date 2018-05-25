module SAML2.WebSSO.XML.Meta
  ( SPDescPre(..), SPDesc(..)
  , spdValidUntil
  , spdCacheDuration
  , spdOrgName
  , spdOrgDisplayName
  , spdOrgURL
  , spdResponseURL

  , spDesc
  , spMeta
  ) where

import Data.List.NonEmpty
import Data.Maybe
import Data.Proxy
import Data.String.Conversions
import Data.Time
import GHC.Stack
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO.SP
import SAML2.WebSSO.Types
import SAML2.WebSSO.XML
import Text.XML
import Text.XML.Cursor
import Text.XML.Util
import URI.ByteString

import qualified Network.URI as OldURI
import qualified SAML2.Bindings.Identifiers as HS
import qualified SAML2.Core.Datatypes as HS hiding (AnyURI)
import qualified SAML2.Core.Identifiers as HS
import qualified SAML2.Metadata.Metadata as HS
import qualified SAML2.XML as HX hiding (AnyURI)
import qualified SAML2.XML.Schema.Datatypes as HX
import qualified SAML2.XML.Signature.Types as HX


-- | 'HS.Descriptor', but without exposing the use of hsaml2.
newtype SPDesc = SPDesc Document
  deriving (Eq, Show)

instance HasXML SPDesc where
  parse (node -> NodeElement el) = pure . SPDesc $ Document defPrologue el defMiscellaneous
  parse bad = die (Proxy @SPDesc) bad

instance HasXMLRoot SPDesc where
  renderRoot (SPDesc (Document _ el _)) = el


-- | high-level, condensed data uesd for constructing an 'SPDesc'.  what is not in here is set to
-- some constant default.
data SPDescPre = SPDescPre
  { _spdValidUntil     :: UTCTime          -- TODO: Time
  , _spdCacheDuration  :: NominalDiffTime  -- TODO: Duration
  , _spdOrgName        :: ST
  , _spdOrgDisplayName :: ST
  , _spdOrgURL         :: URI
  , _spdResponseURL    :: URI
  }
  deriving (Eq, Show)

makeLenses ''SPDescPre


spDesc :: SP m => ST -> URI -> URI -> m SPDescPre
spDesc nick org resp = do
  let _spdCacheDuration  = months 1
      _spdOrgName        = nick
      _spdOrgDisplayName = nick
      _spdOrgURL         = org
      _spdResponseURL    = resp

      years  n = days n * 365
      months n = days n * 30
      days   n = n * 60 * 60 * 24

  _spdValidUntil        <- addUTCTime (years 1) . fromTime <$> getNow
  pure SPDescPre {..}


-- | TODO: this can throw async errors!  this shouldn't be necessary!
spMeta :: HasCallStack => SPDescPre -> SPDesc
spMeta spdesc = either (error . show) SPDesc . parseLBS def . HX.samlToXML $ spMeta' spdesc

-- | [4/2.6]
spMeta' :: HasCallStack => SPDescPre -> HS.Descriptor
spMeta' spdesc = HS.SPSSODescriptor
    { HS.descriptorRole = HS.RoleDescriptor
      { HS.roleDescriptorID = Just "e3a565aa-1392-4446-a4d6-3771453808f0" :: Maybe HS.ID
      , HS.roleDescriptorValidUntil = Just (spdesc ^. spdValidUntil) :: Maybe HS.DateTime
      , HS.roleDescriptorCacheDuration = Just (spdesc ^. spdCacheDuration) :: Maybe HX.Duration
      , HS.roleDescriptorProtocolSupportEnumeration = [fromJust $ OldURI.parseURI "urn:oasis:names:tc:SAML:2.0:protocol"] :: [HX.AnyURI]
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
      , HS.roleDescriptorContactPerson = [HS.ContactPerson  -- TODO
        { HS.contactType = HS.ContactTypeSupport
        , HS.contactAttrs = []
        , HS.contactExtensions = HS.Extensions []
        , HS.contactCompany = Just "evil corp."
        , HS.contactGivenName = Just "Dr."
        , HS.contactSurName = Just "Girlfriend"
        , HS.contactEmailAddress = [fromJust $ OldURI.parseURI "email:president@evil.corp"] :: [HX.AnyURI]
        , HS.contactTelephoneNumber = ["+314159265"]
        }] :: [HS.Contact]
      }
    , HS.descriptorSSO = HS.SSODescriptor
      { HS.ssoDescriptorArtifactResolutionService = [] :: [HS.IndexedEndpoint]
      , HS.ssoDescriptorSingleLogoutService = [] :: [HS.Endpoint]
      , HS.ssoDescriptorManageNameIDService = [] :: [HS.Endpoint]
      , HS.ssoDescriptorNameIDFormat = [ {- "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" -}] :: [HX.IdentifiedURI HS.NameIDFormat]  -- TODO
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
    }


castURL :: URI -> HX.URI
castURL = fromJust . OldURI.parseURI . cs . renderURI
