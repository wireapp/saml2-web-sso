{-# LANGUAGE StrictData          #-}
{-# LANGUAGE OverloadedStrings   #-}

module SAML2.WebSSO.Types where

import Control.Lens (makePrisms)  -- FUTUREWORK: this is missing in microlens-th
import Control.Monad.Except
import Data.Aeson
import Data.Aeson.TH
import Data.List.NonEmpty
import Data.Maybe
import Data.Monoid ((<>))
import Data.String.Conversions (ST, cs)
import Data.Time (UTCTime(..), NominalDiffTime, formatTime, defaultTimeLocale, addUTCTime)
import Data.UUID as UUID
import GHC.Generics (Generic)
import GHC.Stack
import Lens.Micro
import Lens.Micro.TH
import SAML2.WebSSO.Orphans ()
import SAML2.WebSSO.Types.TH (deriveJSONOptions)
import Text.XML.Util
import URI.ByteString  -- FUTUREWORK: should saml2-web-sso also use the URI from http-types?  we already
                       -- depend on that via xml-conduit anyway.  (is it a problem though that it is
                       -- string-based?  is it less of a problem because we need it anyway?)

import qualified Data.Text as ST
import qualified Data.X509 as X509
import qualified Servant
import qualified Text.XML as XML


----------------------------------------------------------------------
-- high-level

data AccessVerdict =
    AccessDenied
    { _avReasons :: [ST]
    }
  | AccessGranted
    { _avUserId :: UserRef
    }
  deriving (Eq, Show, Generic)

data UserRef = UserRef { _uidTenant :: Issuer, _uidSubject :: NameID }
  deriving (Eq, Show, Generic)

-- | More correctly, an 'Issuer' is a 'NameID', but we only support 'URI'.
newtype Issuer = Issuer { _fromIssuer :: URI }
  deriving (Eq, Ord, Show, Generic)

instance FromJSON Issuer where
  parseJSON = withText "Issuer" $ \uri -> case parseURI' uri of
    Right i  -> pure $ Issuer i
    Left msg -> fail $ "Issuer: " <> show msg

instance ToJSON Issuer where
  toJSON = toJSON . renderURI . _fromIssuer


----------------------------------------------------------------------
-- meta [4/2.3.2]

-- | 'HS.Descriptor', but without exposing the use of hsaml2.
newtype SPDesc = SPDesc XML.Document
  deriving (Eq, Show, Generic)

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
  , _spdContacts       :: NonEmpty ContactPerson
  }
  deriving (Eq, Show, Generic)

-- | [4/2.3.2.2].  Zero or more persons are required in metainfo document [4/2.4.1].
data ContactPerson = ContactPerson
  { _cntType      :: ContactType
  , _cntCompany   :: Maybe ST
  , _cntGivenName :: Maybe ST
  , _cntSurname   :: Maybe ST
  , _cntEmail     :: Maybe URI
  , _cntPhone     :: Maybe ST
  }
  deriving (Eq, Show, Generic)

data ContactType
  = ContactTechnical
  | ContactSupport
  | ContactAdministrative
  | ContactBilling
  | ContactOther
  deriving (Eq, Enum, Bounded, Show, Generic)

data IdPDesc = IdPDesc
  { _edIssuer      :: Issuer
  , _edRequestURI  :: URI
  , _edPublicKeys  :: [X509.SignedCertificate]
  }
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- idp info

newtype IdPId = IdPId { fromIdPId :: UUID } deriving (Eq, Show, Generic, Ord)

type IdPConfig_ = IdPConfig ()

data IdPConfig extra = IdPConfig
  { _idpId              :: IdPId
  , _idpMetadata        :: URI
  , _idpIssuer          :: Issuer  -- ^ can be found in metadata
  , _idpRequestUri      :: URI  -- ^ can be found in metadata
  , _idpPublicKey       :: X509.SignedCertificate  -- ^ can be found in metadata
                           -- TODO: azure has 3 (three!) public keys that it signs the assertions
                           -- with, so we need to maintain a list there!
  , _idpExtraInfo       :: extra
  }
  deriving (Eq, Show, Generic)

-- | 'IdPConfig' contains some info that will be filled in by the server when processing the
-- creation request.  'NewIdP' is the type of the data provided by the client in this request.
data NewIdP = NewIdP
  { _nidpMetadata        :: URI
  , _nidpIssuer          :: Issuer  -- TODO: remove this field, it's redundant.  (this will also shorten the list of possible errors in the UI.)
  , _nidpRequestUri      :: URI     -- TODO: dito.
  , _nidpPublicKey       :: X509.SignedCertificate
  }
  deriving (Eq, Show, Generic)


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
  deriving (Eq, Show, Generic)

-- | [1/3.2.2.1]
data Comparison = Exact | Minimum | Maximum | Better
  deriving (Eq, Show, Generic)

data RequestedAuthnContext = RequestedAuthnContext
  { _rqacAuthnContexts :: [ST] -- ^ either classRef or declRef
  , _rqacComparison    :: Comparison
  } deriving (Eq, Show, Generic)

-- | [1/3.4.1.1]
data NameIdPolicy = NameIdPolicy
  { _nidFormat          :: Maybe ST
  , _nidSpNameQualifier :: Maybe ST
  , _nidAllowCreate     :: Maybe Bool
  } deriving (Eq, Show, Generic)

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
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- misc

-- | [1/1.3.3] (we mostly introduce this type to override the unparseable default 'Show' instance.)
newtype Time = Time { fromTime :: UTCTime }
  deriving (Eq, Ord, Generic)

timeFormat :: String
timeFormat = "%Y-%m-%dT%H:%M:%S%QZ"

instance Show Time where
  showsPrec _ (Time t) = showString . show $ formatTime defaultTimeLocale timeFormat t

data Duration = Duration  -- TODO: https://www.w3.org/TR/xmlschema-2/#duration
  deriving (Eq, Show, Generic)

addTime :: NominalDiffTime -> Time -> Time  -- TODO: use 'Duration' instaed of 'NominalDiffTime'
addTime n (Time t) = Time $ addUTCTime n t

-- | IDs must be globally unique between all communication parties and adversaries with a negligible
-- failure probability.  We should probably just use UUIDv4, but we may not have any choice.  [1/1.3.4]
newtype ID m = ID { renderID :: ST }
  deriving (Eq, Ord, Show, Generic)

-- | [1/2.2.1]
data BaseID = BaseID
  { _baseID        :: ST
  , _baseIDNameQ   :: Maybe ST
  , _baseIDSPNameQ :: Maybe ST
  }
  deriving (Eq, Show, Generic)

-- | [1/2.2.2], [1/2.2.3], [1/3.4.1.1], see 'mkNameID' implementation for constraints on this type.
data NameID = NameID
  { _nameID             :: UnqualifiedNameID
  , _nameIDNameQ        :: Maybe ST
  , _nameIDSPNameQ      :: Maybe ST
  , _nameIDSPProvidedID :: Maybe ST
  }
  deriving (Eq, Ord, Show, Generic)

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
  deriving (Eq, Ord, Show, Generic)

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

-- | Extract the 'UnqualifiedNameID' part from the input and render it to a 'ST'.  If there are any
-- qualifiers, return 'Nothing' to prevent name clashes (where two inputs are different, but produce
-- the same output).
shortShowNameID :: NameID -> Maybe ST
shortShowNameID (NameID uqn Nothing Nothing Nothing) = case uqn of
  NameIDFUnspecified st  -> Just st
  NameIDFEmail       st  -> Just st
  NameIDFX509        st  -> Just st
  NameIDFWindows     st  -> Just st
  NameIDFKerberos    st  -> Just st
  NameIDFEntity      uri -> Just $ renderURI uri
  NameIDFPersistent  st  -> Just st
  NameIDFTransient   st  -> Just st
shortShowNameID _ = Nothing


data Version = Version_2_0
  deriving (Eq, Show, Bounded, Enum, Generic)

-- | [1/3.2.2.1;3.2.2.2]
data Status =
    StatusSuccess
  | StatusFailure ST
  deriving (Eq, Show, Generic)


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
  deriving (Eq, Show, Generic)

-- | Conditions that must hold for an 'Assertion' to be actually asserted by the IdP.  [1/2.5]
data Conditions
  = Conditions
    { _condNotBefore           :: Maybe Time
    , _condNotOnOrAfter        :: Maybe Time
    , _condOneTimeUse          :: Bool   -- ^ [1/2.5.1.5]
    , _condAudienceRestriction :: Maybe (NonEmpty URI)  -- ^ 'Nothing' means do not restrict.
    }
  deriving (Eq, Show, Generic)

-- | [1/2.3.3], [3/4.1.4.2]
data SubjectAndStatements
  = SubjectAndStatements
    { _sasSubject    :: Subject
    , _sasStatements :: NonEmpty Statement
    }
  deriving (Eq, Show, Generic)

-- | Information about the client and/or user attempting to authenticate / authorize against the SP.
-- [1/2.4]
data Subject = Subject
  { _subjectID            :: NameID  -- ^ every 'BaseID' is also a 'NameID'; encryption is not supported.
  , _subjectConfirmations :: [SubjectConfirmation]
  }
  deriving (Eq, Show, Generic)

-- | Information about the kind of proof of identity the 'Subject' provided to the IdP.  [1/2.4]
data SubjectConfirmation = SubjectConfirmation
  { _scMethod :: SubjectConfirmationMethod
  , _scData   :: [SubjectConfirmationData]
  }
  deriving (Eq, Show, Generic)

-- | [3/4.1.4.2]
--
-- TODO: we should implement the rest of the options here.  this may be relevant for some clients,
-- and we are not required to base our access policy on it.
data SubjectConfirmationMethod
  = SubjectConfirmationMethodBearer  -- ^ @"urn:oasis:names:tc:SAML:2.0:cm:bearer"@
  deriving (Eq, Show, Enum, Bounded, Generic)

-- | See 'SubjectConfirmation'.  [1/2.4.1.2], [3/4.1.4.2]
data SubjectConfirmationData = SubjectConfirmationData
  { _scdNotBefore    :: Maybe Time
  , _scdNotOnOrAfter :: Time
  , _scdRecipient    :: URI
  , _scdInResponseTo :: Maybe (ID AuthnRequest)
  , _scdAddress      :: Maybe IP  -- ^ it's ok to ignore this
  }
  deriving (Eq, Show, Generic)

newtype IP = IP ST
  deriving (Eq, Show, Generic)

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
  deriving (Eq, Show, Generic)


-- | [1/2.7.2.1]
data Locality = Locality
  { _localityAddress :: Maybe ST
  , _localityDNSName :: Maybe ST
  }
  deriving (Eq, Show, Generic)


-- | [1/2.7.3.1]
data Attribute =
    Attribute
    { _stattrName         :: ST
    , _stattrNameFormat   :: Maybe URI  -- ^ [1/8.2]
    , _stattrFriendlyName :: Maybe ST
    , _stattrValues       :: [AttributeValue]
    }
  deriving (Eq, Show, Generic)

-- | [1/2.7.3.1.1] could be @ST@, or @Num n => n@, or something else.
newtype AttributeValue = AttributeValueUntyped ST
  deriving (Eq, Show, Generic)


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
makeLenses ''ContactPerson
makeLenses ''Duration
makeLenses ''ID
makeLenses ''IdPConfig
makeLenses ''IdPDesc
makeLenses ''Issuer
makeLenses ''Locality
makeLenses ''NameID
makeLenses ''NameIdPolicy
makeLenses ''NewIdP
makeLenses ''RequestedAuthnContext
makeLenses ''Response
makeLenses ''SPDescPre
makeLenses ''Statement
makeLenses ''Status
makeLenses ''Subject
makeLenses ''SubjectAndStatements
makeLenses ''SubjectConfirmation
makeLenses ''SubjectConfirmationData
makeLenses ''Time
makeLenses ''UnqualifiedNameID
makeLenses ''UserRef
makeLenses ''Version

makePrisms ''Statement
makePrisms ''UnqualifiedNameID

deriveJSON deriveJSONOptions ''IdPConfig
deriveJSON deriveJSONOptions ''NewIdP

instance FromJSON IdPId where
  parseJSON value = (>>= maybe unerror (pure . IdPId) . UUID.fromText) . parseJSON $ value
    where unerror = fail ("could not parse config: " <> (show value))

instance ToJSON IdPId where
  toJSON = toJSON . UUID.toText . fromIdPId

idPIdToST :: IdPId -> ST
idPIdToST = UUID.toText . fromIdPId

instance Servant.FromHttpApiData IdPId where
    parseUrlPiece piece = case UUID.fromText piece of
      Nothing -> Left . cs $ "no valid UUID-piece " ++ show piece
      Just uid -> return $ IdPId uid

deriveJSON deriveJSONOptions ''ContactPerson
deriveJSON deriveJSONOptions ''ContactType

instance FromJSON Version where
  parseJSON (String "SAML2.0") = pure Version_2_0
  parseJSON bad = fail $ "could not parse config: bad version string: " <> show bad

instance ToJSON Version where
  toJSON Version_2_0 = String "SAML2.0"


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
