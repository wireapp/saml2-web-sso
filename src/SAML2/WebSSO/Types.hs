{-# LANGUAGE StrictData          #-}
{-# LANGUAGE OverloadedStrings   #-}

module SAML2.WebSSO.Types where

import           Control.Lens
import           Control.Monad.Except
import           Data.Aeson                    as Aeson
import           Data.Aeson.TH
import           Data.List.NonEmpty
import           Data.Maybe
import           Data.Monoid                              ( (<>) )
import           Data.String.Conversions                  ( ST
                                                          , cs
                                                          )
import           Data.Time                                ( UTCTime(..)
                                                          , NominalDiffTime
                                                          , formatTime
                                                          , parseTimeM
                                                          , defaultTimeLocale
                                                          , addUTCTime
                                                          )
import           Data.UUID                     as UUID
import           GHC.Generics                             ( Generic )
import           GHC.Stack
import           SAML2.Util
import           SAML2.WebSSO.Orphans                     ( )
import           SAML2.WebSSO.Types.TH                    ( deriveJSONOptions )
import           URI.ByteString  -- FUTUREWORK: should saml2-web-sso also use the URI from http-types?  we already
                       -- depend on that via xml-conduit anyway.  (is it a problem though that it is
                       -- string-based?  is it less of a problem because we need it anyway?)

import qualified Data.List                     as L
import qualified Data.Text                     as ST
import qualified Data.X509                     as X509
import qualified Servant


----------------------------------------------------------------------
-- high-level

data AccessVerdict =
    AccessDenied
    { _avReasons :: [DeniedReason]  -- ^ (this is morally a set, but lists are often easier to handle)
    }
  | AccessGranted
    { _avUserId :: UserRef
    }
  deriving (Eq, Show, Generic)

data DeniedReason
  = DeniedStatusFailure
  | DeniedBadUserRefs { deniedDetails :: String }
  | DeniedBadInResponseTos { deniedDetails :: String }
  | DeniedIssueInstantNotInPast { deniedTimestamp :: Time, deniedNow :: Time }
  | DeniedAssertionIssueInstantNotInPast { deniedTimestamp :: Time, deniedNow :: Time }
  | DeniedAuthnStatementIssueInstantNotInPast { deniedTimestamp :: Time, deniedNow :: Time }
  | DeniedBadDestination { deniedWeExpected :: String, deniedTheyExpected :: String }
  | DeniedBadRecipient { deniedWeExpected :: String, deniedTheyExpected :: String }
  | DeniedIssuerMismatch { deniedInHeader :: Maybe Issuer, deniedInAssertion :: Issuer }
  | DeniedNoStatements
  | DeniedNoAuthnStatement
  | DeniedAuthnStatmentExpiredAt { deniedEndOfLife :: Time }
  | DeniedNoBearerConfSubj
  | DeniedBearerConfAssertionsWithoutAudienceRestriction
  | DeniedNotOnOrAfterSubjectConfirmation { deniedNotOnOrAfter :: Time }
  | DeniedNotBeforeSubjectConfirmation { deniedNotBefore :: Time }
  | DeniedNotOnOrAfterCondition { deniedNotOnOrAfter :: Time }
  | DeniedNotBeforeCondition { deniedNotBefore :: Time }
  | DeniedAudienceMismatch { deniedWeExpectedAudience :: URI, deniedTheyExpectedAudience :: NonEmpty URI }
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

-- | high-level, condensed data uesd for constructing an 'SPDesc'.  what is not in here is set to
-- some constant default.
data SPMetadata = SPMetadata
  { _spID             :: ID SPMetadata
  , _spValidUntil     :: UTCTime          -- FUTUREWORK: Time
  , _spCacheDuration  :: NominalDiffTime  -- FUTUREWORK: Duration
  , _spOrgName        :: ST
  , _spOrgDisplayName :: ST
  , _spOrgURL         :: URI
  , _spResponseURL    :: URI
  , _spContacts       :: NonEmpty ContactPerson
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

data IdPMetadata = IdPMetadata
  { _edIssuer            :: Issuer
  , _edRequestURI        :: URI
  , _edCertAuthnResponse :: NonEmpty X509.SignedCertificate
    -- ^ There can be lots of certs for one IdP.  In particular, azure offers more than one key for
    -- authentication response signing, with no indication in the metadata file which will be used.
  }
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- idp info

newtype IdPId = IdPId { fromIdPId :: UUID } deriving (Eq, Show, Generic, Ord)

type IdPConfig_ = IdPConfig ()

data IdPConfig extra = IdPConfig
  { _idpId              :: IdPId
  , _idpMetadata        :: IdPMetadata
  , _idpExtraInfo       :: extra
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
  , _rqIssueInstant     :: Time
  , _rqIssuer           :: Issuer

    -- extended xml type
  , _rqNameIDPolicy     :: Maybe NameIdPolicy
    -- ^ [1/3.4.1] Allow the IdP to create unknown users implicitly if their subject identifier has
    -- the right form.
    --
    -- NB: Using email addresses as unique identifiers between IdP and SP causes problems, since
    -- email addresses can change over time.  The best option may be to use UUIDs instead, and
    -- provide email addresses in SAML 'AuthnResponse' attributes or via scim.
    --
    -- Quote from the specs:
    --
    -- [3/4.1.4.1] If the service provider wishes to permit the identity provider to establish a new
    -- identifier for the principal if none exists, it MUST include a NameIDPolicy element with the
    -- AllowCreate attribute set to "true". Otherwise, only a principal for whom the identity
    -- provider has previously established an identifier usable by the service provider can be
    -- authenticated successfully.

  -- ...  (e.g. attribute requests)
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
  { _nidFormat          :: NameIDFormat
  , _nidSpNameQualifier :: Maybe ST
  , _nidAllowCreate     :: Bool  -- ^ default: 'False'
  } deriving (Eq, Show, Generic)

-- | [1/3.4]
type AuthnResponse = Response (NonEmpty Assertion)

-- | [1/3.2.2]
data Response payload = Response
  { _rspID           :: ID (Response payload)
  , _rspInRespTo     :: Maybe (ID AuthnRequest)
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

data Duration = Duration  -- TODO: https://www.w3.org/TR/xmlschema-2/#duration. one this is one,
                          -- grep this package for uses of NominalDiffTime and replace them.
  deriving (Eq, Show, Generic)

addTime :: NominalDiffTime -> Time -> Time
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
data NameIDFormat
  = NameIDFUnspecified  -- ^ 'nameIDNameQ', 'nameIDSPNameQ' SHOULD be omitted.
  | NameIDFEmail
  | NameIDFX509
  | NameIDFWindows
  | NameIDFKerberos
  | NameIDFEntity
  | NameIDFPersistent   -- ^ use UUIDv4 where we have the choice.
  | NameIDFTransient
  deriving (Eq, Ord, Enum, Bounded, Show, Generic)

-- | [1/8.3]
type family NameIDReprFormat (t :: NameIDFormat) where
  NameIDReprFormat 'NameIDFUnspecified = ST
  NameIDReprFormat 'NameIDFEmail       = ST
  NameIDReprFormat 'NameIDFX509        = ST
  NameIDReprFormat 'NameIDFWindows     = ST
  NameIDReprFormat 'NameIDFKerberos    = ST
  NameIDReprFormat 'NameIDFEntity      = URI
  NameIDReprFormat 'NameIDFPersistent  = ST
  NameIDReprFormat 'NameIDFTransient   = ST

-- | [1/8.3]  (FUTUREWORK: there may be a way to make this nicer by using 'NameIDFormat', 'NameIDReprFormat'.
data UnqualifiedNameID
  = UNameIDUnspecified ST  -- ^ 'nameIDNameQ', 'nameIDSPNameQ' SHOULD be omitted.
  | UNameIDEmail       ST
  | UNameIDX509        ST
  | UNameIDWindows     ST
  | UNameIDKerberos    ST
  | UNameIDEntity      URI
  | UNameIDPersistent  ST  -- ^ use UUIDv4 where we have the choice.
  | UNameIDTransient   ST
  deriving (Eq, Ord, Show, Generic)

mkNameID
  :: MonadError String m
  => UnqualifiedNameID
  -> Maybe ST
  -> Maybe ST
  -> Maybe ST
  -> m NameID
mkNameID nid@(UNameIDEntity uri) m1 m2 m3 = do
  mapM_ throwError
    $ [ "mkNameID: nameIDNameQ, nameIDSPNameQ, nameIDSPProvidedID MUST be omitted for entity NameIDs."
          <> show [m1, m2, m3]
      | all isJust [m1, m2, m3]
      ]
    <> [ "mkNameID: entity URI too long: " <> show uritxt
       | uritxt <- [renderURI uri]
       , ST.length uritxt > 1024
       ]
  pure $ NameID nid Nothing Nothing Nothing
mkNameID nid@(UNameIDPersistent txt) m1 m2 m3 = do
  mapM_ throwError
    $ [ "mkNameID: persistent text too long: " <> show (nid, ST.length txt)
      | ST.length txt > 1024
      ]
  pure $ NameID nid m1 m2 m3
mkNameID nid m1 m2 m3 = do
  pure $ NameID nid m1 m2 m3

opaqueNameID :: ST -> NameID
opaqueNameID raw = NameID (UNameIDUnspecified raw) Nothing Nothing Nothing

entityNameID :: URI -> NameID
entityNameID uri = NameID (UNameIDEntity uri) Nothing Nothing Nothing

nameIDFormat :: HasCallStack => NameIDFormat -> String
nameIDFormat = \case
  NameIDFUnspecified -> "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  NameIDFEmail -> "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  NameIDFX509 -> "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
  NameIDFWindows ->
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
  NameIDFKerberos   -> "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
  NameIDFEntity     -> "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  NameIDFPersistent -> "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  NameIDFTransient  -> "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

unameIDFormat :: HasCallStack => UnqualifiedNameID -> String
unameIDFormat = \case
  UNameIDUnspecified _ ->
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  UNameIDEmail _ -> "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  UNameIDX509  _ -> "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
  UNameIDWindows _ ->
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
  UNameIDKerberos   _ -> "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
  UNameIDEntity     _ -> "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  UNameIDPersistent _ -> "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  UNameIDTransient  _ -> "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

-- | Extract the 'UnqualifiedNameID' part from the input and render it to a 'ST'.  If there are any
-- qualifiers, return 'Nothing' to prevent name clashes (where two inputs are different, but produce
-- the same output).
shortShowNameID :: NameID -> Maybe ST
shortShowNameID (NameID uqn Nothing Nothing Nothing) = case uqn of
  UNameIDUnspecified st  -> Just st
  UNameIDEmail       st  -> Just st
  UNameIDX509        st  -> Just st
  UNameIDWindows     st  -> Just st
  UNameIDKerberos    st  -> Just st
  UNameIDEntity      uri -> Just $ renderURI uri
  UNameIDPersistent  st  -> Just st
  UNameIDTransient   st  -> Just st
shortShowNameID _ = Nothing


-- | [1/3.2.2.1;3.2.2.2] This is a simple custom boolean type.  We really don't need any more
-- information than that.
data Status = StatusSuccess | StatusFailure
  deriving (Eq, Show, Bounded, Enum, Generic)


----------------------------------------------------------------------
-- assertion

-- | What the IdP has to say to the SP about the 'Subject'.  In essence, an 'Assertion' is a
-- 'Subject' and a set of 'Statement's on that 'Subject'.  [1/2.3.3]
data Assertion
  = Assertion
    { _assID            :: ID Assertion
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
    , _condOneTimeUse          :: Bool   -- ^ [1/2.5.1.5] (it's safe to ignore this)
    , _condAudienceRestriction :: [NonEmpty URI]  -- ^ [1/2.5.1.4] this is an and of ors ('[]' means
                                                  -- do not restrict).
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
  , _scData   :: Maybe SubjectConfirmationData
  }
  deriving (Eq, Show, Generic)

-- | [3/3] there is also @holder-of-key@ and @sender-vouches@, but the first seems a bit esoteric
-- and the second is just silly, so this library only supports @bearer@.
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
    , _astSessionIndex        :: Maybe ST  -- safe to ignore
    , _astSessionNotOnOrAfter :: Maybe Time
    , _astSubjectLocality     :: Maybe Locality
    }
  deriving (Eq, Show, Generic)


-- | [1/2.7.2.1]
data Locality = Locality
  { _localityAddress :: Maybe IP
  , _localityDNSName :: Maybe ST
  }
  deriving (Eq, Show, Generic)


----------------------------------------------------------------------
-- helper functions

-- | pull statements from different assertions of same shape into the same assertion.
-- [1/2.3.3]
normalizeAssertion :: [Assertion] -> [Assertion]
normalizeAssertion = error "normalizeAssertion: not implemented"


----------------------------------------------------------------------
-- misc instances

makeLenses ''AccessVerdict
makeLenses ''Assertion
makeLenses ''AuthnRequest
makeLenses ''BaseID
makeLenses ''Comparison
makeLenses ''Conditions
makeLenses ''ContactPerson
makeLenses ''Duration
makeLenses ''ID
makeLenses ''IdPConfig
makeLenses ''IdPMetadata
makeLenses ''Issuer
makeLenses ''Locality
makeLenses ''NameID
makeLenses ''NameIdPolicy
makeLenses ''RequestedAuthnContext
makeLenses ''Response
makeLenses ''SPMetadata
makeLenses ''Statement
makeLenses ''Subject
makeLenses ''SubjectAndStatements
makeLenses ''SubjectConfirmation
makeLenses ''SubjectConfirmationData
makeLenses ''Time
makeLenses ''UnqualifiedNameID
makeLenses ''UserRef

makePrisms ''AccessVerdict
makePrisms ''Statement
makePrisms ''UnqualifiedNameID

deriveJSON deriveJSONOptions ''IdPMetadata
deriveJSON deriveJSONOptions ''IdPConfig

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

instance Servant.ToHttpApiData IdPId where
    toUrlPiece = idPIdToST

deriveJSON deriveJSONOptions ''ContactPerson
deriveJSON deriveJSONOptions ''ContactType

instance Servant.FromHttpApiData (ID a) where
  parseUrlPiece = fmap ID . Servant.parseUrlPiece

instance Servant.ToHttpApiData (ID a) where
  toUrlPiece = Servant.toUrlPiece . renderID

instance Servant.FromHttpApiData Time where
  parseUrlPiece st =
    fmap Time . parseTimeM True defaultTimeLocale timeFormat =<< Servant.parseUrlPiece @String st

instance Servant.ToHttpApiData Time where
  toUrlPiece =
    Servant.toUrlPiece . formatTime defaultTimeLocale timeFormat . fromTime

instance FromJSON Status
instance ToJSON Status

instance FromJSON DeniedReason
instance ToJSON DeniedReason

instance FromJSON AuthnResponse
instance ToJSON AuthnResponse

instance FromJSON Assertion
instance ToJSON Assertion

instance FromJSON SubjectAndStatements
instance ToJSON SubjectAndStatements

instance FromJSON Subject
instance ToJSON Subject

instance FromJSON SubjectConfirmation
instance ToJSON SubjectConfirmation

instance FromJSON SubjectConfirmationMethod
instance ToJSON SubjectConfirmationMethod

instance FromJSON SubjectConfirmationData
instance ToJSON SubjectConfirmationData

instance FromJSON IP
instance ToJSON IP

instance FromJSON Statement
instance ToJSON Statement

instance FromJSON Locality
instance ToJSON Locality

instance FromJSON (ID a)
instance ToJSON (ID a)

instance FromJSON NameID
instance ToJSON NameID

instance FromJSON UnqualifiedNameID
instance ToJSON UnqualifiedNameID

instance FromJSON Time
instance ToJSON Time

instance FromJSON Conditions
instance ToJSON Conditions


----------------------------------------------------------------------
-- hand-crafted lenses, accessors

-- | To counter replay attacks we need to store 'Assertions' until they invalidate.  If
-- 'condNotOnOrAfter' is not specified, assume 'assIssueInstant' plus 30 days.
assEndOfLife :: Lens' Assertion Time
assEndOfLife = lens gt st
 where
  fallback :: Assertion -> Time
  fallback ass = addTime (30 * 24 * 60 * 60) (ass ^. assIssueInstant)

  gt :: Assertion -> Time
  gt ass =
    fromMaybe (fallback ass)
      . (^? to _assConditions . _Just . to _condNotOnOrAfter . _Just)
      $ ass

  st :: Assertion -> Time -> Assertion
  st ass tim = ass & assConditions . _Just . condNotOnOrAfter .~ Just tim

-- | [3/4.1.4.2] SubjectConfirmation [...] If the containing message is in response to an
-- AuthnRequest, then the InResponseTo attribute MUST match the request's ID.
rspInResponseTo :: MonadError String m => AuthnResponse -> m (ID AuthnRequest)
rspInResponseTo aresp = case (inResp, inSubjectConf) of
  (_, []) -> throwError "not found"  -- the inSubjectConf is required!
  (Nothing, js@(_ : _)) | L.length (L.nub js) /= 1 ->
    throwError
      $  "mismatching inResponseTo attributes in subject confirmation data: "
      <> show js
  (Just i, js@(_ : _)) | L.length (L.nub (i : js)) /= 1 ->
    throwError
      $ "mismatching inResponseTo attributes in response header, subject confirmation data: "
      <> show (i, js)
  (_, (j : _)) -> pure j
 where
  inSubjectConf :: [ID AuthnRequest]
  inSubjectConf =
    maybeToList
      .   (^. scdInResponseTo)
      =<< maybeToList
      .   (^. scData)
      =<< (^. assContents . sasSubject . subjectConfirmations)
      =<< toList (aresp ^. rspPayload)

  inResp :: Maybe (ID AuthnRequest)
  inResp = aresp ^. rspInRespTo

getUserRef :: (HasCallStack, MonadError String m) => AuthnResponse -> m UserRef
getUserRef resp = do
  let assertions = resp ^. rspPayload

  issuer :: Issuer <- case nub $ (^. assIssuer) <$> assertions of
    i :| [] -> pure i
    bad     -> throwError $ "bad issuers: " <> show bad

  subject :: NameID <-
    case nub $ (^. assContents . sasSubject) <$> assertions of
      Subject s _ :| [] -> pure s
      bad               -> throwError $ "bad subjects: " <> show bad

  pure $ UserRef issuer subject


----------------------------------------------------------------------
-- why is this not in the resp. packages?

nelConcat :: NonEmpty (NonEmpty a) -> NonEmpty a
nelConcat ((x :| xs) :| ys) = x :| mconcat (xs : (toList <$> ys))

(<$$>) :: (Functor f, Functor g) => (a -> b) -> f (g a) -> f (g b)
(<$$>) = fmap . fmap
