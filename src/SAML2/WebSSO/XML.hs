{-# LANGUAGE OverloadedStrings #-}

-- FUTUREWORK: consider using http://hackage.haskell.org/package/xml-conduit-parse

module SAML2.WebSSO.XML where

import Control.Category (Category(..))
import Control.Exception (SomeException)
import Control.Lens
import Control.Monad
import Control.Monad.Except
import Data.EitherR
import Data.Foldable (toList)
import Data.List.NonEmpty as NL (NonEmpty((:|)), nonEmpty)
import Data.Maybe (fromMaybe, catMaybes)
import Data.Monoid ((<>))
import Data.String.Conversions
import Data.Time
import Data.Typeable (Proxy(Proxy), Typeable)
import GHC.Stack
import Prelude hiding ((.), id)
import SAML2.Util
import SAML2.WebSSO.Types
import Text.XML hiding (renderText)
import URI.ByteString

import qualified Data.List as List
import qualified Network.URI as HS
import qualified SAML2.Core as HS
import qualified SAML2.Core.Protocols as HS
import qualified SAML2.Profiles as HS
import qualified SAML2.XML as HS
import qualified Text.XML
import qualified Text.XML.HXT.Arrow.Pickle.Xml as HS


defNameSpaces :: [(ST, ST)]
defNameSpaces =
  [ ("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
  , ("samla", "urn:oasis:names:tc:SAML:2.0:assertion")
  , ("samlm", "urn:oasis:names:tc:SAML:2.0:metadata")
  , ("ds", "http://www.w3.org/2000/09/xmldsig#")
  ]


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


importAuthnRequest :: MonadError String m => HS.AuthnRequest -> m AuthnRequest
importAuthnRequest req = do
  let proto = HS.requestProtocol $ HS.authnRequest req
  () <- importVersion $ HS.protocolVersion proto
  _rqID           <- importID $ HS.protocolID proto
  _rqIssueInstant <- importTime $ HS.protocolIssueInstant proto
  _rqIssuer       <- importRequiredIssuer $ HS.protocolIssuer proto
  _rqNameIDPolicy <- fmapFlipM importNameIDPolicy $ HS.authnRequestNameIDPolicy req

  fmapFlipM importURI (HS.protocolDestination proto) >>= \case
    Nothing -> pure ()
    Just dest -> die (Proxy @AuthnRequest) ("protocol destination not allowed: " <> show dest)

  pure AuthnRequest {..}

exportAuthnRequest :: AuthnRequest -> HS.AuthnRequest
exportAuthnRequest req = (defAuthnRequest proto)
  { HS.authnRequestNameIDPolicy = exportNameIDPolicy <$> req ^. rqNameIDPolicy
  }
  where
    proto = (defProtocolType (exportID $ req ^. rqID) (exportTime $ req ^. rqIssueInstant))
      { HS.protocolVersion = exportVersion
      , HS.protocolIssuer = exportRequiredIssuer $ req ^. rqIssuer
      , HS.protocolDestination = Nothing
      }

instance HasXML     AuthnRequest     where parse      = wrapParse importAuthnRequest
instance HasXMLRoot AuthnRequest     where renderRoot = wrapRenderRoot exportAuthnRequest

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


importNameIDPolicy :: (HasCallStack, MonadError String m) => HS.NameIDPolicy -> m NameIdPolicy
importNameIDPolicy nip = do
  _nidFormat             <- importNameIDFormat $ HS.nameIDPolicyFormat nip
  let _nidSpNameQualifier = cs <$> HS.nameIDPolicySPNameQualifier nip
      _nidAllowCreate     = HS.nameIDPolicyAllowCreate nip
  pure NameIdPolicy {..}

exportNameIDPolicy :: HasCallStack => NameIdPolicy -> HS.NameIDPolicy
exportNameIDPolicy nip = HS.NameIDPolicy
  { HS.nameIDPolicyFormat          = exportNameIDFormat $ nip ^. nidFormat
  , HS.nameIDPolicySPNameQualifier = cs <$> nip ^. nidSpNameQualifier
  , HS.nameIDPolicyAllowCreate     = nip ^. nidAllowCreate
  }

importNameIDFormat :: (HasCallStack, MonadError String m) => HS.IdentifiedURI HS.NameIDFormat -> m NameIDFormat
importNameIDFormat = \case
  HS.Identified HS.NameIDFormatUnspecified     -> pure NameIDFUnspecified
  HS.Identified HS.NameIDFormatEmail           -> pure NameIDFEmail
  HS.Identified HS.NameIDFormatX509            -> pure NameIDFX509
  HS.Identified HS.NameIDFormatWindows         -> pure NameIDFWindows
  HS.Identified HS.NameIDFormatKerberos        -> pure NameIDFKerberos
  HS.Identified HS.NameIDFormatEntity          -> pure NameIDFEntity
  HS.Identified HS.NameIDFormatPersistent      -> pure NameIDFPersistent
  HS.Identified HS.NameIDFormatTransient       -> pure NameIDFTransient
  bad@(HS.Identified HS.NameIDFormatEncrypted) -> throwError $ "unsupported: " <> show bad
  bad@(HS.Unidentified _)                      -> throwError $ "unsupported: " <> show bad

exportNameIDFormat :: NameIDFormat -> HS.IdentifiedURI HS.NameIDFormat
exportNameIDFormat = \case
  NameIDFUnspecified -> HS.Identified HS.NameIDFormatUnspecified
  NameIDFEmail       -> HS.Identified HS.NameIDFormatEmail
  NameIDFX509        -> HS.Identified HS.NameIDFormatX509
  NameIDFWindows     -> HS.Identified HS.NameIDFormatWindows
  NameIDFKerberos    -> HS.Identified HS.NameIDFormatKerberos
  NameIDFEntity      -> HS.Identified HS.NameIDFormatEntity
  NameIDFPersistent  -> HS.Identified HS.NameIDFormatPersistent
  NameIDFTransient   -> HS.Identified HS.NameIDFormatTransient


importAuthnResponse :: (HasCallStack, MonadError String m) => HS.Response -> m AuthnResponse
importAuthnResponse rsp = do
  let rsptyp :: HS.StatusResponseType = HS.response rsp
      proto  :: HS.ProtocolType       = HS.statusProtocol rsptyp

  () <- importVersion $ HS.protocolVersion proto
  _rspID           <- importID $ HS.protocolID proto
  _rspInRespTo     <- (importID . cs) `fmapFlipM` HS.statusInResponseTo rsptyp
  _rspIssueInstant <- importTime $ HS.protocolIssueInstant proto
  _rspDestination  <- fmapFlipM importURI $ HS.protocolDestination proto
  _rspIssuer       <- importOptionalIssuer $ HS.protocolIssuer proto
  _rspStatus       <- importStatus $ HS.status rsptyp
  _rspPayload      <- maybe (throwError "no assertions") pure . NL.nonEmpty =<< (importAssertion `mapM` HS.responseAssertions rsp)

  -- ignore: @HS.protocolSignature proto :: Maybe SAML2.XML.Signature.Types.Signature@
  -- ignore: @HS.relayState proto :: Maybe SAML2.Bindings.General.RelayState@

  pure Response {..}

exportAuthnResponse :: HasCallStack => AuthnResponse -> HS.Response
exportAuthnResponse rsp = HS.Response
  { HS.response             = HS.StatusResponseType
    { HS.statusProtocol     = HS.ProtocolType
      { HS.protocolID           = exportID (rsp ^. rspID)
      , HS.protocolVersion      = exportVersion
      , HS.protocolIssueInstant = exportTime (rsp ^. rspIssueInstant)
      , HS.protocolDestination  = exportURI <$> (rsp ^. rspDestination)
      , HS.protocolConsent      = HS.Identified HS.ConsentUnspecified  -- [1/8.4.1] there are no rules how to process the consent value.
      , HS.protocolIssuer       = exportIssuer <$> (rsp ^. rspIssuer) :: Maybe HS.Issuer
      , HS.protocolSignature    = Nothing
      , HS.protocolExtensions   = []
      , HS.relayState           = Nothing
      }
    , HS.statusInResponseTo = exportID <$> (rsp ^. rspInRespTo)
    , HS.status             = exportStatus (rsp ^. rspStatus)
    }
  , HS.responseAssertions   = toList $ exportAssertion <$> (rsp ^. rspPayload)
  }

instance HasXML     AuthnResponse    where parse      = wrapParse importAuthnResponse
instance HasXMLRoot AuthnResponse    where renderRoot = wrapRenderRoot exportAuthnResponse

importAssertion :: (HasCallStack, MonadError String m) => HS.PossiblyEncrypted HS.Assertion -> m Assertion
importAssertion bad@(HS.SoEncrypted _) = die (Proxy @Assertion) bad
importAssertion (HS.NotEncrypted ass) = do
  () <- importVersion $ HS.assertionVersion ass
  _assID           <- importID $ HS.assertionID ass
  _assIssueInstant <- importTime $ HS.assertionIssueInstant ass
  _assIssuer       <- importIssuer $ HS.assertionIssuer ass
  _assConditions   <- fmapFlipM importConditions $ HS.assertionConditions ass
  _assContents     <- do
    subj  <- importSubject $ HS.assertionSubject ass
    when (null $ HS.assertionStatement ass) $
      die (Proxy @Assertion) ("no statements" :: String)
    mstmts <- importStatement `mapM` HS.assertionStatement ass
    case catMaybes mstmts of
      stmt:stmts -> pure $ SubjectAndStatements subj (stmt :| stmts)
      [] -> die (Proxy @Assertion) ("no statements" :: String)

  unless (null $ HS.assertionAdvice ass) $
    die (Proxy @Assertion) (HS.assertionAdvice ass)

  pure Assertion {..}

exportAssertion :: HasCallStack => Assertion -> HS.PossiblyEncrypted HS.Assertion
exportAssertion ass = HS.NotEncrypted HS.Assertion
  { HS.assertionVersion      = exportVersion
  , HS.assertionID           = exportID (ass ^. assID)
  , HS.assertionIssueInstant = exportTime (ass ^. assIssueInstant)
  , HS.assertionIssuer       = exportIssuer (ass ^. assIssuer)
  , HS.assertionSignature    = Nothing  -- signatures are handled before parsing.
  , HS.assertionSubject      = exportSubject $ ass ^. assContents . sasSubject
  , HS.assertionConditions   = exportConditions <$> (ass ^. assConditions)
  , HS.assertionAdvice       = Nothing
  , HS.assertionStatement    = exportStatement <$> (ass ^. assContents . sasStatements . to toList)
  }

importSubject :: (HasCallStack, MonadError String m) => HS.Subject -> m Subject
importSubject (HS.Subject Nothing _) = die (Proxy @Subject) ("need to provide a subject" :: String)
importSubject (HS.Subject (Just (HS.SoEncrypted _)) _) = die (Proxy @Subject) ("encrypted subjects not supported" :: String)
importSubject (HS.Subject (Just (HS.NotEncrypted sid)) scs) = case sid of
  HS.IdentifierName nameid -> do
    nameid' <- importNameID nameid
    Subject nameid' <$> importSubjectConfirmation nameid' `mapM` scs
  bad@(HS.IdentifierBase _baseid) -> do
    die (Proxy @Subject) ("unsupported subject identifier: " <> show bad)

exportSubject :: (HasCallStack) => Subject -> HS.Subject
exportSubject subj = HS.Subject (Just (HS.NotEncrypted sid)) scs
  where
    sid :: HS.Identifier
    sid = HS.IdentifierName $ exportNameID (subj ^. subjectID)

    scs :: [HS.SubjectConfirmation]
    scs = exportSubjectConfirmation <$> subj ^. subjectConfirmations


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
      = SubjectConfirmation SubjectConfirmationMethodBearer <$> importSubjectConfirmationData `mapM` confdata

exportSubjectConfirmation :: (HasCallStack) => SubjectConfirmation -> HS.SubjectConfirmation
exportSubjectConfirmation (SubjectConfirmation SubjectConfirmationMethodBearer scd) =
  HS.SubjectConfirmation (HS.Identified HS.ConfirmationMethodBearer) Nothing $ exportSubjectConfirmationData <$> scd


importSubjectConfirmationData :: (HasCallStack, MonadError String m) => HS.SubjectConfirmationData -> m SubjectConfirmationData
importSubjectConfirmationData (HS.SubjectConfirmationData notbefore (Just notonorafter) (Just recipient) inresp confaddr _ _) =
  SubjectConfirmationData
  <$> importTime `fmapFlipM` notbefore
  <*> importTime notonorafter
  <*> importURI recipient
  <*> importID `fmapFlipM` inresp
  <*> importIP `fmapFlipM` confaddr

  -- ignore: 'HS.subjectConfirmationKeyInfo' (this is only required for holder of key subjects
  -- [3/3.1], [1/2.4.1.2], [1/2.4.1.4])
  -- ignore: 'HS.subjectConfirmationXML' (there is nothing we can assume about it's semantics)

importSubjectConfirmationData bad@(HS.SubjectConfirmationData _ Nothing _ _ _ _ _) =
  die (Proxy @SubjectConfirmationData) ("missing NotOnOrAfter: " <> show bad)
importSubjectConfirmationData bad@(HS.SubjectConfirmationData _ _ Nothing _ _ _ _) =
  die (Proxy @SubjectConfirmationData) ("missing Recipient: " <> show bad)

exportSubjectConfirmationData :: (HasCallStack) => SubjectConfirmationData -> HS.SubjectConfirmationData
exportSubjectConfirmationData scd = HS.SubjectConfirmationData
  { HS.subjectConfirmationNotBefore    = exportTime <$> scd ^. scdNotBefore
  , HS.subjectConfirmationNotOnOrAfter = Just . exportTime $ scd ^. scdNotOnOrAfter
  , HS.subjectConfirmationRecipient    = Just . exportURI $ scd ^. scdRecipient
  , HS.subjectConfirmationInResponseTo = cs . renderID <$> scd ^. scdInResponseTo
  , HS.subjectConfirmationAddress      = exportIP <$> scd ^. scdAddress
  , HS.subjectConfirmationKeyInfo      = mempty
  , HS.subjectConfirmationXML          = mempty
  }

instance HasXML SubjectConfirmationData where
  parse = wrapParse importSubjectConfirmationData
  render = wrapRender exportSubjectConfirmationData

importIP :: (HasCallStack, MonadError String m) => HS.IP -> m IP
importIP = pure . IP . cs

exportIP :: (HasCallStack) => IP -> HS.IP
exportIP (IP s) = cs s

importConditions :: forall m. (HasCallStack, MonadError String m) => HS.Conditions -> m Conditions
importConditions conds = do
  _condNotBefore <- fmapFlipM importTime $ HS.conditionsNotBefore conds
  _condNotOnOrAfter <- fmapFlipM importTime $ HS.conditionsNotOnOrAfter conds
  let _condOneTimeUse = False
      _condAudienceRestriction = []

      go :: Conditions -> HS.Condition -> m Conditions
      go conds' HS.OneTimeUse =
        pure $ conds' & condOneTimeUse .~ True

      go conds' (HS.AudienceRestriction hsrs) = do
        rs :: NonEmpty URI <- (importURI . HS.audience) `mapM` hsrs
        pure $ conds' & condAudienceRestriction %~ (rs:)

      go _ badcond = die (Proxy @Conditions) ("unsupported condition" :: String, badcond)

  foldM go (Conditions {..}) (HS.conditions conds)

exportConditions :: (HasCallStack) => Conditions -> HS.Conditions
exportConditions conds = HS.Conditions
  { HS.conditionsNotBefore    = exportTime <$> conds ^. condNotBefore
  , HS.conditionsNotOnOrAfter = exportTime <$> conds ^. condNotOnOrAfter
  , HS.conditions             = [ HS.OneTimeUse | conds ^. condOneTimeUse ]
                             <> [ HS.AudienceRestriction (HS.Audience . exportURI <$> hsrs)
                                | hsrs <- conds ^. condAudienceRestriction
                                ]
  }

instance HasXML Conditions where
  parse = wrapParse importConditions
  render = wrapRender exportConditions

-- | Attribute statements are silently ignored.
importStatement :: (HasCallStack, MonadError String m)
                => HS.Statement -> m (Maybe Statement)
importStatement (HS.StatementAttribute _) = pure Nothing
importStatement (HS.StatementAuthn st) = Just <$> do
  _astAuthnInstant <- importTime $ HS.authnStatementInstant st
  let _astSessionIndex = cs <$> HS.authnStatementSessionIndex st
  _astSessionNotOnOrAfter <- fmapFlipM importTime $ HS.authnStatementSessionNotOnOrAfter st
  _astSubjectLocality     <- fmapFlipM importLocality $ HS.authnStatementSubjectLocality st
  -- NB: @HS.authnStatementContext st@ is ignored [1/2.7.2.2].
  pure AuthnStatement {..}

importStatement bad = die (Proxy @Statement) bad

exportStatement :: (HasCallStack) => Statement -> HS.Statement
exportStatement AuthnStatement{..} = HS.StatementAuthn HS.AuthnStatement
  { HS.authnStatementInstant             = exportTime _astAuthnInstant
  , HS.authnStatementSessionIndex        = cs <$> _astSessionIndex
  , HS.authnStatementSessionNotOnOrAfter = exportTime <$> _astSessionNotOnOrAfter
  , HS.authnStatementSubjectLocality     = exportLocality <$> _astSubjectLocality
  , HS.authnStatementContext             = HS.AuthnContext Nothing Nothing []
  }


importLocality :: (HasCallStack, MonadError String m) => HS.SubjectLocality -> m Locality
importLocality loc = Locality
  <$> (fmapFlipM importIP $ HS.subjectLocalityAddress loc)
  <*> pure (cs <$> HS.subjectLocalityDNSName loc)

exportLocality :: HasCallStack => Locality -> HS.SubjectLocality
exportLocality loc = HS.SubjectLocality
  { HS.subjectLocalityAddress = exportIP <$> loc ^. localityAddress
  , HS.subjectLocalityDNSName = cs <$> loc ^. localityDNSName
  }


importID :: (HasCallStack, MonadError String m) => HS.ID -> m (ID a)
importID = pure . ID . cs

exportID :: HasCallStack => ID a -> HS.ID
exportID (ID t) = cs t

importBaseID :: (HasCallStack, ConvertibleStrings s ST) => HS.BaseID s -> BaseID
importBaseID (HS.BaseID bidq bidspq bid) = BaseID (cs bid) (cs <$> bidq) (cs <$> bidspq)

importBaseIDasNameID :: (HasCallStack, ConvertibleStrings s ST) => HS.BaseID s -> NameID
importBaseIDasNameID (importBaseID -> BaseID bid bidq bidspq) =
  NameID (UNameIDUnspecified bid) bidq bidspq Nothing

importNameID :: (HasCallStack, MonadError String m) => HS.NameID -> m NameID
importNameID bad@(HS.NameID (HS.BaseID _ _ _) (HS.Unidentified _) _)
  = die (Proxy @NameID) (show bad)
importNameID (HS.NameID (HS.BaseID m1 m2 nid) (HS.Identified hsNameIDFormat) m3)
  = either (die (Proxy @NameID)) pure $
    form hsNameIDFormat (cs nid) >>= \nid' -> mkNameID nid' (cs <$> m1) (cs <$> m2) (cs <$> m3)
  where
    form :: MonadError String m => HS.NameIDFormat -> ST -> m UnqualifiedNameID
    form HS.NameIDFormatUnspecified = pure . UNameIDUnspecified
    form HS.NameIDFormatEmail       = pure . UNameIDEmail
    form HS.NameIDFormatX509        = pure . UNameIDX509
    form HS.NameIDFormatWindows     = pure . UNameIDWindows
    form HS.NameIDFormatKerberos    = pure . UNameIDKerberos
    form HS.NameIDFormatEntity      = fmap UNameIDEntity . parseURI'
    form HS.NameIDFormatPersistent  = pure . UNameIDPersistent
    form HS.NameIDFormatTransient   = pure . UNameIDTransient
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
    unform (UNameIDUnspecified n) = (HS.Identified HS.NameIDFormatUnspecified, n)
    unform (UNameIDEmail       n) = (HS.Identified HS.NameIDFormatEmail, n)
    unform (UNameIDX509        n) = (HS.Identified HS.NameIDFormatX509, n)
    unform (UNameIDWindows     n) = (HS.Identified HS.NameIDFormatWindows, n)
    unform (UNameIDKerberos    n) = (HS.Identified HS.NameIDFormatKerberos, n)
    unform (UNameIDEntity      n) = (HS.Identified HS.NameIDFormatEntity, renderURI n)
    unform (UNameIDPersistent  n) = (HS.Identified HS.NameIDFormatPersistent, n)
    unform (UNameIDTransient   n) = (HS.Identified HS.NameIDFormatTransient, n)

nameIDToST :: NameID -> ST
nameIDToST (NameID (UNameIDUnspecified txt) Nothing Nothing Nothing) = txt
nameIDToST (NameID (UNameIDEmail txt) Nothing Nothing Nothing) = txt
nameIDToST (NameID (UNameIDEntity uri) Nothing Nothing Nothing) = renderURI uri
nameIDToST other = cs $ encodeElem other  -- (some of the others may also have obvious
                                          -- serializations, but we don't need them for now.)

instance HasXML NameID where
  parse = wrapParse importNameID
  render = wrapRender exportNameID

userRefToST :: UserRef -> ST
userRefToST (UserRef (Issuer tenant) subject) = "{" <> renderURI tenant <> "}" <> nameIDToST subject

importVersion :: (HasCallStack, MonadError String m) => HS.SAMLVersion -> m ()
importVersion HS.SAML20 = pure ()
importVersion bad = die (Proxy @HS.SAMLVersion) bad

exportVersion :: HasCallStack => HS.SAMLVersion
exportVersion = HS.SAML20

importTime :: (HasCallStack, MonadError String m) => HS.DateTime -> m Time
importTime = pure . Time

exportTime :: HasCallStack => Time -> HS.DateTime
exportTime = fromTime

importURI :: (HasCallStack, MonadError String m) => HS.URI -> m URI
importURI uri = parseURI' . cs $ HS.uriToString id uri mempty

exportURI :: HasCallStack => URI -> HS.URI
exportURI uri = fromMaybe err . HS.parseURIReference . cs . renderURI $ uri
  where err = error $ "internal error: " <> show uri

-- | [1/3.2.2.1;3.2.2.2]
importStatus :: (HasCallStack, Monad m) => HS.Status -> m Status
importStatus = pure . \case
  HS.Status (HS.StatusCode HS.StatusSuccess _) _ _ -> StatusSuccess
  _ -> StatusFailure

exportStatus :: HasCallStack => Status -> HS.Status
exportStatus = \case
  StatusSuccess -> HS.Status (HS.StatusCode HS.StatusSuccess []) Nothing Nothing
  StatusFailure -> HS.Status (HS.StatusCode HS.StatusRequester []) Nothing Nothing

instance HasXML Status where
  parse = wrapParse importStatus
  render = wrapRender exportStatus

importIssuer :: (HasCallStack, MonadError String m) => HS.Issuer -> m Issuer
importIssuer = fmap Issuer . (nameIDToURI <=< importNameID) . HS.issuer
  where
    nameIDToURI (NameID (UNameIDEntity uri) Nothing Nothing Nothing) = pure uri
    nameIDToURI bad = die (Proxy @Issuer) bad

exportIssuer :: HasCallStack => Issuer -> HS.Issuer
exportIssuer = HS.Issuer . exportNameID . entityNameID . _fromIssuer

instance HasXML Issuer where
  parse = wrapParse importIssuer
  render = wrapRender exportIssuer

importOptionalIssuer :: (HasCallStack, MonadError String m) => Maybe HS.Issuer -> m (Maybe Issuer)
importOptionalIssuer = fmapFlipM importIssuer

exportOptionalIssuer :: HasCallStack => Maybe Issuer -> Maybe HS.Issuer
exportOptionalIssuer = fmap exportIssuer

importRequiredIssuer :: (HasCallStack, MonadError String m) => Maybe HS.Issuer -> m Issuer
importRequiredIssuer = maybe (die (Proxy @AuthnRequest) ("no issuer id" :: String)) importIssuer

exportRequiredIssuer :: HasCallStack => Issuer -> Maybe HS.Issuer
exportRequiredIssuer = Just . exportIssuer
