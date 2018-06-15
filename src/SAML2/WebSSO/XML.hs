module SAML2.WebSSO.XML where

import Control.Category (Category(..))
import Control.Exception (SomeException)
import Control.Monad
import Control.Monad.Except
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe (fromMaybe, isNothing, maybeToList, catMaybes)
import Data.Monoid ((<>))
import Data.String.Conversions
import Data.Time
import Data.Typeable (Proxy(Proxy), Typeable)
import GHC.Stack
import Lens.Micro
import Prelude hiding ((.), id)
import SAML2.WebSSO.Types
import Text.Show.Pretty (ppShow)
import Text.XML hiding (renderText)
import Text.XML.Iso
import Text.XML.Util
import URI.ByteString

import qualified Data.List as List
import qualified Data.Tree.NTree.TypeDefs as HS
import qualified Network.URI as HS
import qualified SAML2.Core as HS
import qualified SAML2.Core.Protocols as HS
import qualified SAML2.Metadata as HS
import qualified SAML2.Profiles as HS
import qualified SAML2.XML as HS
import qualified Text.XML
import qualified Text.XML.HXT.Arrow.Pickle.Xml as HS
import qualified Text.XML.HXT.DOM.TypeDefs as HS

----------------------------------------------------------------------
-- HasXML class

encode :: forall a. HasXMLRoot a => a -> LT
encode = Text.XML.renderText settings . renderToDocument
  where
    settings = def { rsNamespaces = nameSpaces (Proxy @a), rsXMLDeclaration = False }

decode :: forall m a. (HasXMLRoot a, MonadError String m) => LT -> m a
decode = either (throwError . show @SomeException) parseFromDocument . parseText def

encodeElem :: forall a. HasXML a => a -> LT
encodeElem = Text.XML.renderText settings . mkDocument' . render
  where
    settings = def { rsNamespaces = nameSpaces (Proxy @a), rsXMLDeclaration = False }
    mkDocument' [NodeElement el] = mkDocument el
    mkDocument' bad = error $ "encodeElem: " <> show bad

decodeElem :: forall a m. (HasXML a, MonadError String m) => LT -> m a
decodeElem = either (throwError . show @SomeException) parseFromDocument . parseText def


renderToDocument :: HasXMLRoot a => a -> Document
renderToDocument = mkDocument . renderRoot

parseFromDocument :: (HasXML a, MonadError String m) => Document -> m a
parseFromDocument doc = parse [NodeElement $ documentRoot doc]


-- FUTUREWORK: perhaps we want to split this up: HasXML (for nameSpaces), and HasXMLParse, HasXMLRender,
-- and drop the assymetric, little used render function from HasXML?

class HasXML a where
  nameSpaces :: Proxy a -> [(ST, ST)]
  nameSpaces Proxy = defNameSpaces

  render :: a -> [Node]
  default render :: HasXMLRoot a => a -> [Node]
  render = (:[]) . NodeElement . renderRoot

  parse  :: MonadError String m => [Node] -> m a

class HasXML a => HasXMLRoot a where
  renderRoot :: a -> Element


instance HasXML Document where
  parse [NodeElement el] = pure $ Document defPrologue el defMiscellaneous
  parse bad = die (Proxy @Document) bad

instance HasXMLRoot Document where
  renderRoot (Document _ el _) = el


----------------------------------------------------------------------
-- util

-- | Do not use this in production!  It works, but it's slow and failures are a bit violent.
unsafeReadTime :: HasCallStack => String -> Time
unsafeReadTime s = either (error ("decodeTime: " <> show s)) id $ decodeTime s

decodeTime :: (MonadError String m, ConvertibleStrings s String) => s -> m Time
decodeTime (cs -> s) = case parseTimeM True defaultTimeLocale timeFormat s of
  Just t  -> pure $ Time t
  Nothing -> die (Proxy @Time) (s, timeFormat)

renderTime :: Time -> ST
renderTime (Time utctime) =
  cs . accomodateMSAD $ formatTime defaultTimeLocale timeFormat utctime
  where
    -- more than 7 decimal points make Active Directory choke.
    accomodateMSAD :: String -> String
    accomodateMSAD s = case List.elemIndex '.' s of
      Nothing -> s
      Just i -> case List.splitAt i s of
        (t, u) -> case List.splitAt 8 u of
          (_, "") -> t <> u
          (v, _)  -> t <> v <> "Z"


----------------------------------------------------------------------
-- hack: use hsaml2 parsers and convert from SAMLProtocol instances

wrapParse :: forall (m :: * -> *) them us.
             (HasCallStack, MonadError String m, HS.XmlPickler them, HasXML us, Typeable us)
          => (them -> m us) -> [Node] -> m us
wrapParse imprt [NodeElement xml] = either (die (Proxy @us) . (, xml)) imprt $
                                    HS.xmlToSAML (renderLBS def $ Document defPrologue xml defMiscellaneous)
wrapParse _ badxml = error $ "internal error: " <> show badxml

wrapRender :: forall them us.
              (HasCallStack, HS.XmlPickler them, HasXML us)
           => (us -> them) -> us -> [Node]
wrapRender exprt = parseElement . HS.samlToXML . exprt
  where
    parseElement lbs = case parseLBS def lbs of
      Right (Document _ el _) -> [NodeElement el]
      Left msg  -> error $ show (Proxy @us, msg)

wrapRenderRoot :: forall them us.
              (HasCallStack, HS.SAMLProtocol them, HasXMLRoot us)
           => (us -> them) -> us -> Element
wrapRenderRoot exprt = parseElement . HS.samlToXML . exprt
  where
    parseElement lbs = case parseLBS def lbs of
      Right (Document _ el _) -> el
      Left msg  -> error $ show (Proxy @us, msg)

instance HasXML     AuthnRequest     where parse      = wrapParse importAuthnRequest
instance HasXMLRoot AuthnRequest     where renderRoot = wrapRenderRoot exportAuthnRequest
instance HasXML     AuthnResponse    where parse      = wrapParse importAuthnResponse
instance HasXMLRoot AuthnResponse    where renderRoot = wrapRenderRoot exportAuthnResponse

instance HasXML NameID where
  parse = wrapParse importNameID
  render = wrapRender exportNameID

instance HasXML Issuer where
  parse = wrapParse importIssuer
  render = wrapRender exportIssuer


importEntityDescriptor :: (HasCallStack, MonadError String m) => HS.Descriptor -> m EntityDescriptor
importEntityDescriptor = error . ppShow

exportEntityDescriptor :: HasCallStack => EntityDescriptor -> HS.Descriptor
exportEntityDescriptor = error . ppShow


importAuthnRequest :: MonadError String m => HS.AuthnRequest -> m AuthnRequest
importAuthnRequest req = do
  let proto = HS.requestProtocol $ HS.authnRequest req
  _rqID           <- importID $ HS.protocolID proto
  _rqVersion      <- importVersion $ HS.protocolVersion proto
  _rqIssueInstant <- importTime $ HS.protocolIssueInstant proto
  _rqIssuer       <- importRequiredIssuer $ HS.protocolIssuer proto
  Nothing         <- fmapFlipM importURI $ HS.protocolDestination proto

  -- TODO: make sure everything in HS.AuthnRequest that might change the interpreation of the data
  -- we know is 'Nothing'.  also do this on all other 'import*' functions.  (or should we only do
  -- this once we have our own parsers only based on stack-prism and xml-conduit?)
  pure AuthnRequest {..}

exportAuthnRequest :: AuthnRequest -> HS.AuthnRequest
exportAuthnRequest req = defAuthnRequest proto
  where
    proto = (defProtocolType (exportID $ req ^. rqID) (exportTime $ req ^. rqIssueInstant))
      { HS.protocolVersion = exportVersion $ req ^. rqVersion
      , HS.protocolIssuer = exportRequiredIssuer $ req ^. rqIssuer
      , HS.protocolDestination = Nothing
      }

defAuthnRequest :: HS.ProtocolType -> HS.AuthnRequest
defAuthnRequest proto = HS.AuthnRequest
  { HS.authnRequest = HS.RequestAbstractType proto
  , HS.authnRequestForceAuthn = False
  , HS.authnRequestIsPassive = False
  , HS.authnRequestAssertionConsumerService = HS.AssertionConsumerServiceURL Nothing Nothing
  , HS.authnRequestAssertionConsumingServiceIndex = Nothing
  , HS.authnRequestProviderName = Nothing
  , HS.authnRequestSubject = Nothing
  , HS.authnRequestNameIDPolicy = Nothing
  , HS.authnRequestConditions = Nothing
  , HS.authnRequestRequestedAuthnContext = Nothing
  , HS.authnRequestScoping = Nothing
  }

defProtocolType :: HS.ID -> HS.DateTime -> HS.ProtocolType
defProtocolType pid iinst = HS.ProtocolType
  { HS.protocolID = pid
  , HS.protocolVersion = HS.SAML20
  , HS.protocolIssueInstant = iinst
  , HS.protocolDestination = Nothing
  , HS.protocolConsent = HS.Identified HS.ConsentUnspecified
  , HS.protocolIssuer = Nothing
  , HS.protocolSignature = Nothing
  , HS.protocolExtensions = []
  , HS.relayState = Nothing
  }


importAuthnResponse :: (HasCallStack, MonadError String m) => HS.Response -> m AuthnResponse
importAuthnResponse rsp = do
  let rsptyp :: HS.StatusResponseType = HS.response rsp
      proto  :: HS.ProtocolType       = HS.statusProtocol rsptyp

  _rspID           <- importID $ HS.protocolID proto
  _rspInRespTo     <- (importID . cs) `fmapFlipM` HS.statusInResponseTo rsptyp
  _rspVersion      <- importVersion $ HS.protocolVersion proto
  _rspIssueInstant <- importTime $ HS.protocolIssueInstant proto
  _rspDestination  <- fmapFlipM importURI $ HS.protocolDestination proto
  _rspIssuer       <- importOptionalIssuer $ HS.protocolIssuer proto
  _rspStatus       <- importStatus $ HS.status rsptyp
  _rspPayload      <- importAssertion `mapM` HS.responseAssertions rsp

  pure Response {..}

exportAuthnResponse :: HasCallStack => AuthnResponse -> HS.Response
exportAuthnResponse = error . ppShow


importAssertion :: (HasCallStack, MonadError String m) => HS.PossiblyEncrypted HS.Assertion -> m Assertion
importAssertion bad@(HS.SoEncrypted _) = die (Proxy @Assertion) bad
importAssertion (HS.NotEncrypted ass) = do
  _assVersion      <- importVersion $ HS.assertionVersion ass
  _assID           <- importID $ HS.assertionID ass
  _assIssueInstant <- importTime $ HS.assertionIssueInstant ass
  _assIssuer       <- importIssuer $ HS.assertionIssuer ass
  _assConditions   <- fmapFlipM importConditions $ HS.assertionConditions ass
  _assContents     <- do
    subj  <- importSubject $ HS.assertionSubject ass
    when (null $ HS.assertionStatement ass) $
      die (Proxy @Assertion) ("no statements" :: String)
    stmt:stmts <- importStatement `mapM` HS.assertionStatement ass
    pure $ SubjectAndStatements subj (stmt :| stmts)

  unless (null $ HS.assertionAdvice ass) $
    die (Proxy @Assertion) (HS.assertionAdvice ass)

  pure Assertion {..}


importSubject :: (HasCallStack, MonadError String m) => HS.Subject -> m Subject
importSubject (HS.Subject Nothing _) = die (Proxy @Subject) ("need to provide a subject" :: String)
importSubject (HS.Subject (Just (HS.SoEncrypted _)) _) = die (Proxy @Subject) ("encrypted subjects not supported" :: String)
importSubject (HS.Subject (Just (HS.NotEncrypted sid)) scs) = case sid of
  HS.IdentifierName HS.NameID
    { HS.nameBaseID = importBaseIDasNameID -> nameid
    , HS.nameIDFormat = ((`elem` [HS.Identified HS.NameIDFormatPersistent, HS.Identified HS.NameIDFormatUnspecified]) -> True)
    , HS.nameSPProvidedID = Nothing
    } -> Subject nameid <$> importSubjectConfirmation nameid `mapM` scs
  bad -> die (Proxy @Subject) ("unsupported subject identifier: " <> show bad)

importSubjectConfirmation :: (HasCallStack, MonadError String m) => NameID -> HS.SubjectConfirmation -> m SubjectConfirmation
importSubjectConfirmation = go
  where
    go _ (HS.SubjectConfirmation meth _ _) | meth /= HS.Identified HS.ConfirmationMethodBearer
      = die (Proxy @SubjectConfirmation) ("unsupported confirmation method: " <> show meth)
    go uid (HS.SubjectConfirmation _ (Just (HS.NotEncrypted (HS.IdentifierName uid'))) _) | Right uid /= fmapL (const ()) (importNameID uid')
      = die (Proxy @SubjectConfirmation) ("uid mismatch: " <> show (uid, uid'))
    go _ (HS.SubjectConfirmation _ (Just bad) _)
      = die (Proxy @SubjectConfirmation) ("unsupported identifier: " <> show bad)
    go _ (HS.SubjectConfirmation _ _ confdata)
      = SubjectConfirmation SubjectConfirmationMethodBearer <$> importSubjectConfirmationData `mapM` maybeToList confdata

importSubjectConfirmationData :: (HasCallStack, MonadError String m) => HS.SubjectConfirmationData -> m SubjectConfirmationData
importSubjectConfirmationData (HS.SubjectConfirmationData notbefore (Just notonorafter) (Just recipient) inresp confaddr _ _) =
  SubjectConfirmationData
  <$> (importTime `fmapFlipM` notbefore)
  <*> importTime notonorafter
  <*> importURI recipient
  <*> importID `fmapFlipM` inresp
  <*> importIP `fmapFlipM` confaddr
importSubjectConfirmationData bad@(HS.SubjectConfirmationData _ Nothing _ _ _ _ _) =
  die (Proxy @SubjectConfirmationData) ("missing NotOnOrAfter: " <> show bad)
importSubjectConfirmationData bad@(HS.SubjectConfirmationData _ _ Nothing _ _ _ _) =
  die (Proxy @SubjectConfirmationData) ("missing Recipient: " <> show bad)

importIP :: (HasCallStack, MonadError String m) => HS.IP -> m IP
importIP = pure . IP . cs


importConditions :: (HasCallStack, MonadError String m) => HS.Conditions -> m Conditions
importConditions conds = do
  _condNotBefore <- fmapFlipM importTime $ HS.conditionsNotBefore conds
  _condNotOnOrAfter <- fmapFlipM importTime $ HS.conditionsNotOnOrAfter conds
  let _condOneTimeUse = HS.OneTimeUse `elem` HS.conditions conds
  _condAudienceRestriction :: Maybe (NonEmpty URI)
    <- do
         let pull (HS.AudienceRestriction us) = Just $ HS.audience <$> us
             pull _ = Nothing
             uris :: [NonEmpty HS.URI] = catMaybes $ pull <$> HS.conditions conds
         case uris of
           [] -> pure Nothing
           (x : xs') -> Just <$> importURI `mapM` nelConcat (x :| xs')

  unless (HS.conditions conds `notElem` [[], [HS.OneTimeUse]]) $
    die (Proxy @Conditions) ("unsupported conditions" :: String, HS.conditions conds)

  pure Conditions {..}


importStatement :: (HasCallStack, MonadError String m)
                => HS.Statement -> m Statement
importStatement (HS.StatementAttribute st) =
  AttributeStatement <$> (importAttribute `mapM` HS.attributeStatement st)
importStatement (HS.StatementAuthn st) = do
  _astAuthnInstant <- importTime $ HS.authnStatementInstant st
  let _astSessionIndex = cs <$> HS.authnStatementSessionIndex st
  -- TODO: not done yet.  in general, we need to check for absence of all fields allowed by the
  -- specs that we don't want to handle.  at least we need to crash if they are present.
  let _astSessionNotOnOrAfter = Nothing
      _astSubjectLocality     = Nothing
  pure AuthnStatement {..}
importStatement bad = die (Proxy @Statement) bad


importAttribute :: (HasCallStack, MonadError String m)
                => HS.PossiblyEncrypted HS.Attribute -> m Attribute
importAttribute bad@(HS.SoEncrypted _) = die (Proxy @Attribute) bad  -- encrypted asseritons are not implemented
importAttribute (HS.NotEncrypted ass) = do
  unless (HS.attributeNameFormat ass == HS.Identified HS.AttributeNameFormatUnspecified) $
    die (Proxy @Attribute) ("unsupported format" :: String, ass)

  unless (isNothing $ HS.attributeFriendlyName ass) $
    die (Proxy @Attribute) ("friendly names are not supported" :: String, ass)

  unless (null $ HS.attributeAttrs ass) $
    die (Proxy @Attribute) ("attributes are not supported" :: String, ass)

  let nm = cs $ HS.attributeName ass
  vals <- importAttributeValue `mapM` HS.attributeValues ass

  pure $ Attribute nm Nothing Nothing vals

importAttributeValue :: (HasCallStack, MonadError String m) => HS.Nodes -> m AttributeValue
importAttributeValue [HS.NTree (HS.XText txt) []] = pure . AttributeValueUntyped $ cs txt
importAttributeValue [ HS.NTree (HS.XAttr qn) [HS.NTree (HS.XText thistype) []]
                     , HS.NTree (HS.XText txt) []
                     ] | qn == HS.newQName (HS.newXName "type") (HS.newXName "xsi") (HS.newXName "http://www.w3.org/2001/XMLSchema-instance")
                         && thistype `elem` ["xs:anyType", "xs:string"]
                       = pure . AttributeValueUntyped $ cs txt
importAttributeValue bad = die (Proxy @AttributeValue) bad


importID :: (HasCallStack, MonadError String m) => HS.ID -> m (ID a)
importID = pure . ID . cs

exportID :: HasCallStack => ID a -> HS.ID
exportID (ID t) = cs t

importBaseID :: (HasCallStack, ConvertibleStrings s ST) => HS.BaseID s -> BaseID
importBaseID (HS.BaseID bidq bidspq bid) = BaseID (cs bid) (cs <$> bidq) (cs <$> bidspq)

importBaseIDasNameID :: (HasCallStack, ConvertibleStrings s ST) => HS.BaseID s -> NameID
importBaseIDasNameID (importBaseID -> BaseID bid bidq bidspq) =
  NameID (NameIDFUnspecified bid) bidq bidspq Nothing

importNameID :: (HasCallStack, MonadError String m) => HS.NameID -> m NameID
importNameID bad@(HS.NameID (HS.BaseID _ _ _) (HS.Unidentified _) _)
  = die (Proxy @NameID) (show bad)
importNameID (HS.NameID (HS.BaseID m1 m2 nid) (HS.Identified hsNameIDFormat) m3)
  = either (die (Proxy @NameID)) pure $
    form hsNameIDFormat (cs nid) >>= \nid' -> mkNameID nid' (cs <$> m1) (cs <$> m2) (cs <$> m3)
  where
    form :: MonadError String m => HS.NameIDFormat -> ST -> m UnqualifiedNameID
    form HS.NameIDFormatUnspecified = pure . NameIDFUnspecified
    form HS.NameIDFormatEmail       = pure . NameIDFEmail
    form HS.NameIDFormatX509        = pure . NameIDFX509
    form HS.NameIDFormatWindows     = pure . NameIDFWindows
    form HS.NameIDFormatKerberos    = pure . NameIDFKerberos
    form HS.NameIDFormatEntity      = fmap NameIDFEntity . parseURI'
    form HS.NameIDFormatPersistent  = pure . NameIDFPersistent
    form HS.NameIDFormatTransient   = pure . NameIDFTransient
    form b@HS.NameIDFormatEncrypted = \_ -> die (Proxy @NameID) (show b)

exportNameID :: NameID -> HS.NameID
exportNameID name = HS.NameID
  { HS.nameBaseID = HS.BaseID (cs <$> name ^. nameIDNameQ) (cs <$> name ^. nameIDSPNameQ) (cs nid)
  , HS.nameIDFormat = fmt
  , HS.nameSPProvidedID = cs <$> name ^. nameIDSPProvidedID
  }
  where
    (fmt, nid) = unform (name ^. nameID)

    unform :: UnqualifiedNameID -> (HS.IdentifiedURI HS.NameIDFormat, ST)
    unform (NameIDFUnspecified n) = (HS.Identified HS.NameIDFormatUnspecified, n)
    unform (NameIDFEmail       n) = (HS.Identified HS.NameIDFormatEmail, n)
    unform (NameIDFX509        n) = (HS.Identified HS.NameIDFormatX509, n)
    unform (NameIDFWindows     n) = (HS.Identified HS.NameIDFormatWindows, n)
    unform (NameIDFKerberos    n) = (HS.Identified HS.NameIDFormatKerberos, n)
    unform (NameIDFEntity      n) = (HS.Identified HS.NameIDFormatEntity, renderURI n)
    unform (NameIDFPersistent  n) = (HS.Identified HS.NameIDFormatPersistent, n)
    unform (NameIDFTransient   n) = (HS.Identified HS.NameIDFormatTransient, n)

importVersion :: (HasCallStack, MonadError String m) => HS.SAMLVersion -> m Version
importVersion HS.SAML20 = pure Version_2_0
importVersion bad = die (Proxy @Version) bad

exportVersion :: HasCallStack => Version -> HS.SAMLVersion
exportVersion Version_2_0 = HS.SAML20

importTime :: (HasCallStack, MonadError String m) => HS.DateTime -> m Time
importTime = pure . Time

exportTime :: HasCallStack => Time -> HS.DateTime
exportTime = fromTime

importURI :: (HasCallStack, MonadError String m) => HS.URI -> m URI
importURI uri = parseURI' . cs $ HS.uriToString id uri mempty

exportURI :: HasCallStack => URI -> HS.URI
exportURI uri = fromMaybe err . HS.parseURIReference . cs . renderURI $ uri
  where err = error $ "internal error: " <> show uri

importStatus :: (HasCallStack, MonadError String m) => HS.Status -> m Status
importStatus (HS.Status (HS.StatusCode HS.StatusSuccess []) Nothing Nothing) = pure StatusSuccess
importStatus status = pure . StatusFailure . cs . show $ status

exportStatus :: HasCallStack => Status -> HS.Status
exportStatus StatusSuccess = HS.Status (HS.StatusCode HS.StatusSuccess []) Nothing Nothing
exportStatus bad = error $ "not implemented: " <> show bad

importIssuer :: (HasCallStack, MonadError String m) => HS.Issuer -> m Issuer
importIssuer = fmap Issuer . (nameIDToURI <=< importNameID) . HS.issuer
  where
    nameIDToURI (NameID (NameIDFEntity uri) Nothing Nothing Nothing) = pure uri
    nameIDToURI bad = die (Proxy @Issuer) bad

exportIssuer :: HasCallStack => Issuer -> HS.Issuer
exportIssuer = HS.Issuer . exportNameID . entityNameID . _fromIssuer

importOptionalIssuer :: (HasCallStack, MonadError String m) => Maybe HS.Issuer -> m (Maybe Issuer)
importOptionalIssuer = fmapFlipM importIssuer

exportOptionalIssuer :: HasCallStack => Maybe Issuer -> Maybe HS.Issuer
exportOptionalIssuer = fmap exportIssuer

importRequiredIssuer :: (HasCallStack, MonadError String m) => Maybe HS.Issuer -> m Issuer
importRequiredIssuer = maybe (die (Proxy @AuthnRequest) ("no issuer id" :: String)) importIssuer

exportRequiredIssuer :: HasCallStack => Issuer -> Maybe HS.Issuer
exportRequiredIssuer = Just . exportIssuer
