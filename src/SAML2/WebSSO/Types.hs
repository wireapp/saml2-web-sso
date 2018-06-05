{-# LANGUAGE StrictData          #-}

module SAML2.WebSSO.Types where

import Control.Lens (makePrisms)  -- FUTUREWORK: this is missing in microlens-th
import Control.Monad.Except
import Data.Aeson
import Data.List.NonEmpty
import Data.Maybe
import Data.Monoid
import Data.String.Conversions (ST)
import Data.Time (UTCTime(..), NominalDiffTime, formatTime, defaultTimeLocale, addUTCTime)
import Data.UUID as UUID
import GHC.Stack
import Lens.Micro
import Lens.Micro.TH
import Text.XML.Util
import URI.ByteString  -- FUTUREWORK: should saml2-web-sso also use the URI from http-types?  we already
                       -- depend on that via xml-conduit anyway.  (is it a probley though that it is
                       -- string-based?  is it less of a problem because we need it anyway?)

import qualified Data.Text as ST


----------------------------------------------------------------------
-- high-level

data AccessVerdict =
    AccessDenied
    { _avReasons :: [ST]
    }
  | AccessGranted
    { _avUserId :: UserId
    }
  deriving (Eq, Show)

data UserId = UserId { _uidTenant :: Issuer, _uidSubject :: NameID }
  deriving (Eq, Show)

-- | More correctly, an 'Issuer' is a 'NameID', but we only support 'URI'.
newtype Issuer = Issuer { _fromIssuer :: URI }
  deriving (Eq, Ord, Show)

mkIssuer :: ST -> Issuer
mkIssuer = Issuer . unsafeParseURI

instance FromJSON Issuer where
  parseJSON = withText "Issuer" $ \uri -> case parseURI' uri of
    Right i  -> pure $ Issuer i
    Left msg -> fail $ "Issuer: " <> show msg

instance ToJSON Issuer where
  toJSON = toJSON . renderURI . _fromIssuer


----------------------------------------------------------------------
-- meta

-- | high-level, condensed data uesd for constructing an 'SPDesc'.  what is not in here is set to
-- some constant default.
data SPDescPre = SPDescPre
  { _spdID             :: UUID.UUID
  , _spdValidUntil     :: UTCTime          -- FUTUREWORK: Time
  , _spdCacheDuration  :: NominalDiffTime  -- FUTUREWORK: Duration
  , _spdOrgName        :: ST
  , _spdOrgDisplayName :: ST
  , _spdOrgURL         :: URI
  , _spdResponseURL    :: URI
  , _spdContacts       :: NonEmpty SPContactPerson
  }
  deriving (Eq, Show)

data SPContactPerson = SPContactPerson
  { _spcntCompany   :: ST
  , _spcntGivenName :: ST
  , _spcntSurname   :: ST
  , _spcntEmail     :: URI
  , _spcntPhone     :: ST
  }
  deriving (Eq, Show)


-- | [4/2.3.2]
data EntityDescriptor = EntityDescriptor
  { _edEntityID      :: ST
  , _edID            :: Maybe (ID EntityDescriptor)
  , _edValidUntil    :: Maybe Time
  , _edCacheDuration :: Maybe Duration
  , _edExtensions    :: [EntityDescriptionExtension]
  , _edRoles         :: [Role]
  }
  deriving (Eq, Show)

data EntityDescriptionExtension =
    EntityDescriptionDigestMethod URI
  | EntityDescriptionSigningMethod URI
  deriving (Eq, Show)

data Role =
    RoleRoleDescriptor RoleDescriptor
  | RoleIDPSSODescriptor IDPSSODescriptor
  | RoleSPSSODescriptor SPSSODescriptor
  deriving (Eq, Show)


-- | [4/2.4.1]
data RoleDescriptor = RoleDescriptor
  { _rssoID                         :: Maybe (ID RoleDescriptor)
  , _rssoValidUntil                 :: Maybe Time
  , _rssoCacheDuration              :: Maybe Duration
  , _rssoProtocolSupportEnumeration :: NonEmpty ST
  , _rssoErrorURL                   :: Maybe URI
  , _rssoKeyDescriptors             :: [KeyDescriptor]
  }
  deriving (Eq, Show)

-- | [4/2.4.1.1]
data KeyDescriptor = KeyDescriptor
  { _kdUse               :: Maybe KeyDescriptorUse
  , _kdKeyInfo           :: ()  -- xml:dsig key (not implemented)
  , _kdEncryptionMethods :: ()  -- xenc method (not implemented)
  }
  deriving (Eq, Show)

data KeyDescriptorUse = KeyDescriptorEncryption | KeyDescriptorSigning
  deriving (Eq, Show, Enum, Bounded)


-- | [4/2.4.4]
data SPSSODescriptor = SPSSODescriptor
  deriving (Eq, Show)


-- | [4/2.4.3]
data IDPSSODescriptor = IDPSSODescriptor
  { _idpWantAuthnRequestsSigned  :: Bool
  , _idpSingleSignOnService      :: NonEmpty EndPointNoRespLoc
  , _idNameIDMappingService      :: [EndPointNoRespLoc]
  , _idAssertionIDRequestService :: [EndPointAllowRespLoc]
  , _idAttributeProfile          :: [URI]
  }
  deriving (Eq, Show)

-- | [4/2.2.2].  Both binding and location should be type 'URI' according to standard, but Microsoft
-- Active Directory has unparseable URIs for locations.
data EndPoint rl = EndPoint
  { _epBinding          :: ST
  , _epLocation         :: URI
  , _epResponseLocation :: rl
  }
  deriving (Eq, Show)

type EndPointNoRespLoc = EndPoint ()
type EndPointAllowRespLoc = EndPoint (Maybe URI)


----------------------------------------------------------------------
-- request, response

-- | [1/3.2.1], [1/3.4], [1/3.4.1]
--
-- (we do not support the Destination attribute; it makes little sense if it is not signed.)
--
-- interpretations of individual providers:
--
-- * <https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference>
data AuthnRequest = AuthnRequest
  { -- abstract xml type
    _rqID               :: ID AuthnRequest
  , _rqVersion          :: Version
  , _rqIssueInstant     :: Time
  , _rqIssuer           :: Issuer

    -- extended xml type (attribute requests, ...)
    -- ...
  }
  deriving (Eq, Show)

-- | [1/3.2.2.1]
data Comparison = Exact | Minimum | Maximum | Better
  deriving (Eq, Show)

data RequestedAuthnContext = RequestedAuthnContext
  { _rqacAuthnContexts :: [ST] -- ^ either classRef or declRef
  , _rqacComparison    :: Comparison
  } deriving (Eq, Show)

-- | [1/3.4.1.1]
data NameIdPolicy = NameIdPolicy
  { _nidFormat          :: Maybe ST
  , _nidSpNameQualifier :: Maybe ST
  , _nidAllowCreate     :: Maybe Bool
  } deriving (Eq, Show)

-- | [1/3.4]
type AuthnResponse = Response [Assertion]

-- | [1/3.2.2]
data Response payload = Response
  { _rspID           :: ID (Response payload)
  , _rspInRespTo     :: Maybe (ID AuthnRequest)
  , _rspVersion      :: Version
  , _rspIssueInstant :: Time
  , _rspDestination  :: Maybe URI
  , _rspIssuer       :: Maybe Issuer
  , _rspStatus       :: Status
  , _rspPayload      :: payload
  }
  deriving (Eq, Show)


----------------------------------------------------------------------
-- misc

-- | [1/1.3.3] (we mostly introduce this type to override the unparseable default 'Show' instance.)
newtype Time = Time { fromTime :: UTCTime }
  deriving (Eq, Ord)

timeFormat :: String
timeFormat = "%Y-%m-%dT%H:%M:%S%QZ"

instance Show Time where
  showsPrec _ (Time t) = showString . show $ formatTime defaultTimeLocale timeFormat t

data Duration = Duration  -- TODO: https://www.w3.org/TR/xmlschema-2/#duration
  deriving (Eq, Show)

addTime :: NominalDiffTime -> Time -> Time  -- TODO: use 'Duration' instaed of 'NominalDiffTime'
addTime n (Time t) = Time $ addUTCTime n t

-- | IDs must be globally unique between all communication parties and adversaries with a negligible
-- failure probability.  We should probably just use UUIDv4, but we may not have any choice.  [1/1.3.4]
newtype ID m = ID { renderID :: ST }
  deriving (Eq, Ord, Show)

-- | [1/2.2.1]
data BaseID = BaseID
  { _baseID        :: ST
  , _baseIDNameQ   :: Maybe ST
  , _baseIDSPNameQ :: Maybe ST
  }
  deriving (Eq, Show)

-- | [1/2.2.2], [1/2.2.3], [1/3.4.1.1], see 'mkNameID' implementation for constraints on this type.
data NameID = NameID
  { _nameID             :: UnqualifiedNameID
  , _nameIDNameQ        :: Maybe ST
  , _nameIDSPNameQ      :: Maybe ST
  , _nameIDSPProvidedID :: Maybe ST
  }
  deriving (Eq, Ord, Show)

-- | [1/8.3]
data UnqualifiedNameID
  = NameIDFUnspecified ST  -- ^ 'nameIDNameQ', 'nameIDSPNameQ' SHOULD be omitted.
  | NameIDFEmail       ST
  | NameIDFX509        ST
  | NameIDFWindows     ST
  | NameIDFKerberos    ST
  | NameIDFEntity      URI
  | NameIDFPersistent  ST  -- ^ use UUIDv4 where we have the choice.
  | NameIDFTransient   ST
  deriving (Eq, Ord, Show)

mkNameID :: MonadError String m => UnqualifiedNameID -> Maybe ST -> Maybe ST -> Maybe ST -> m NameID
mkNameID nid@(NameIDFEntity uri) m1 m2 m3 = do
  mapM_ throwError $
    [ "mkNameID: nameIDNameQ, nameIDSPNameQ, nameIDSPProvidedID MUST be omitted for entity NameIDs."
      <> show [m1, m2, m3]
    | all isJust [m1, m2, m3]
    ] <>
    [ "mkNameID: entity URI too long: "
      <> show uritxt
    | uritxt <- [renderURI uri], ST.length uritxt > 1024
    ]
  pure $ NameID nid Nothing Nothing Nothing
mkNameID nid@(NameIDFPersistent txt) m1 m2 m3 = do
  mapM_ throwError $
    [ "mkNameID: persistent text too long: "
      <> show (nid, ST.length txt)
    | ST.length txt > 1024
    ]
  pure $ NameID nid m1 m2 m3
mkNameID nid m1 m2 m3 = do
  pure $ NameID nid m1 m2 m3

opaqueNameID :: ST -> NameID
opaqueNameID raw = NameID (NameIDFUnspecified raw) Nothing Nothing Nothing

entityNameID :: URI -> NameID
entityNameID uri = NameID (NameIDFEntity uri) Nothing Nothing Nothing

nameIDFormat :: HasCallStack => UnqualifiedNameID -> String
nameIDFormat = \case
  NameIDFUnspecified _ -> "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  NameIDFEmail _       -> "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  NameIDFX509 _        -> "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
  NameIDFWindows _     -> "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
  NameIDFKerberos _    -> "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
  NameIDFEntity _      -> "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  NameIDFPersistent _  -> "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  NameIDFTransient _   -> "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

data Version = Version_2_0
  deriving (Eq, Show, Bounded, Enum)

-- | [1/3.2.2.1;3.2.2.2]
data Status =
    StatusSuccess
  | StatusFailure ST
  deriving (Eq, Show)


----------------------------------------------------------------------
-- assertion

-- | What the IdP has to say to the SP about the 'Subject'.  In essence, an 'Assertion' is a
-- 'Subject' and a set of 'Statement's on that 'Subject'.  [1/2.3.3]
data Assertion
  = Assertion
    { _assVersion       :: Version
    , _assID            :: ID Assertion
    , _assIssueInstant  :: Time
    , _assIssuer        :: Issuer
    , _assConditions    :: Maybe Conditions
    , _assContents      :: SubjectAndStatements
    }
  deriving (Eq, Show)

-- | Conditions that must hold for an 'Assertion' to be actually asserted by the IdP.  [1/2.5]
data Conditions
  = Conditions
    { _condNotBefore           :: Maybe Time
    , _condNotOnOrAfter        :: Maybe Time
    , _condOneTimeUse          :: Bool   -- ^ [1/2.5.1.5]
    , _condAudienceRestriction :: Maybe (NonEmpty URI)  -- ^ 'Nothing' means do not restrict.
    }
  deriving (Eq, Show)

-- | [1/2.3.3], [3/4.1.4.2]
data SubjectAndStatements
  = SubjectAndStatements
    { _sasSubject    :: Subject
    , _sasStatements :: NonEmpty Statement
    }
  deriving (Eq, Show)

-- | Information about the client and/or user attempting to authenticate / authorize against the SP.
-- [1/2.4]
data Subject = Subject
  { _subjectID            :: NameID  -- ^ every 'BaseID' is also a 'NameID'; encryption is not supported.
  , _subjectConfirmations :: [SubjectConfirmation]
  }
  deriving (Eq, Show)

-- | Information about the kind of proof of identity the 'Subject' provided to the IdP.  [1/2.4]
data SubjectConfirmation = SubjectConfirmation
  { _scMethod :: SubjectConfirmationMethod
  , _scData   :: [SubjectConfirmationData]
  }
  deriving (Eq, Show)

-- | [3/4.1.4.2]
--
-- TODO: we should implement the rest of the options here.  this may be relevant for some clients,
-- and we are not required to base our access policy on it.
data SubjectConfirmationMethod
  = SubjectConfirmationMethodBearer  -- ^ @"urn:oasis:names:tc:SAML:2.0:cm:bearer"@
  deriving (Eq, Show, Enum, Bounded)

-- | See 'SubjectConfirmation'.  [1/2.4.1.2], [3/4.1.4.2]
data SubjectConfirmationData = SubjectConfirmationData
  { _scdNotBefore    :: Maybe Time
  , _scdNotOnOrAfter :: Time
  , _scdRecipient    :: URI
  , _scdInResponseTo :: Maybe (ID AuthnRequest)
  , _scdAddress      :: Maybe IP  -- ^ it's ok to ignore this
  }
  deriving (Eq, Show)

newtype IP = IP ST
  deriving (Eq, Show)

-- | The core content of the 'Assertion'.  [1/2.7]
data Statement
  = AuthnStatement  -- [1/2.7.2]
    { _astAuthnInstant        :: Time
    , _astSessionIndex        :: Maybe ST
    , _astSessionNotOnOrAfter :: Maybe Time
    , _astSubjectLocality     :: Maybe Locality
    }
  | AttributeStatement  -- [1/2.7.3]
    { _attrstAttrs :: NonEmpty Attribute
    }
  deriving (Eq, Show)


-- | [1/2.7.2.1]
data Locality = Locality
  { _localityAddress :: Maybe ST
  , _localityDNSName :: Maybe ST
  }
  deriving (Eq, Show)


-- | [1/2.7.3.1]
data Attribute =
    Attribute
    { _stattrName         :: ST
    , _stattrNameFormat   :: Maybe URI  -- ^ [1/8.2]
    , _stattrFriendlyName :: Maybe ST
    , _stattrValues       :: [AttributeValue]
    }
  deriving (Eq, Show)

-- | [1/2.7.3.1.1] could be @ST@, or @Num n => n@, or something else.
newtype AttributeValue = AttributeValueUntyped ST
  deriving (Eq, Show)


----------------------------------------------------------------------
-- helper functions

-- | pull statements from different assertions of same shape into the same assertion.
-- [1/2.3.3]
normalizeAssertion :: [Assertion] -> [Assertion]
normalizeAssertion = error "normalizeAssertion: not implemented"


----------------------------------------------------------------------
-- record field lenses

makeLenses ''AccessVerdict
makeLenses ''Assertion
makeLenses ''Attribute
makeLenses ''AttributeValue
makeLenses ''AuthnRequest
makeLenses ''BaseID
makeLenses ''Comparison
makeLenses ''Conditions
makeLenses ''Duration
makeLenses ''EndPoint
makeLenses ''EntityDescriptionExtension
makeLenses ''EntityDescriptor
makeLenses ''ID
makeLenses ''IDPSSODescriptor
makeLenses ''Issuer
makeLenses ''KeyDescriptor
makeLenses ''KeyDescriptorUse
makeLenses ''Locality
makeLenses ''NameID
makeLenses ''NameIdPolicy
makeLenses ''RequestedAuthnContext
makeLenses ''Response
makeLenses ''Role
makeLenses ''RoleDescriptor
makeLenses ''SPContactPerson
makeLenses ''SPDescPre
makeLenses ''SPSSODescriptor
makeLenses ''Statement
makeLenses ''Status
makeLenses ''Subject
makeLenses ''SubjectAndStatements
makeLenses ''SubjectConfirmation
makeLenses ''SubjectConfirmationData
makeLenses ''Time
makeLenses ''UnqualifiedNameID
makeLenses ''UserId
makeLenses ''Version

makePrisms ''UnqualifiedNameID
makePrisms ''Statement


----------------------------------------------------------------------
-- hand-crafted lenses

-- | To counter replay attacks we need to store 'Assertions' until they invalidate.  If
-- 'condNotOnOrAfter' is not specified, assume 'assIssueInstant' plus 30 days.
assEndOfLife :: Lens' Assertion Time
assEndOfLife = lens gt st
  where
    fallback :: Assertion -> Time
    fallback ass = addTime (30 * 24 * 60 * 60) (ass ^. assIssueInstant)

    gt :: Assertion -> Time
    gt ass = fromMaybe (fallback ass)
            . (^? to _assConditions . _Just . to _condNotOnOrAfter . _Just)
            $ ass

    st :: Assertion -> Time -> Assertion
    st ass tim = ass & assConditions . _Just . condNotOnOrAfter .~ Just tim


----------------------------------------------------------------------
-- why is this not in the resp. packages?

nelConcat :: NonEmpty (NonEmpty a) -> NonEmpty a
nelConcat ((x :| xs) :| ys) = x :| mconcat (xs : (toList <$> ys))

(<$$>) :: (Functor f, Functor g) => (a -> b) -> f (g a) -> f (g b)
(<$$>) = fmap . fmap
