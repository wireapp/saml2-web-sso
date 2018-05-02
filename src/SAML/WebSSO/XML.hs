{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE DefaultSignatures   #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE ViewPatterns        #-}

module SAML.WebSSO.XML where

import Control.Category (Category(..))
import Control.Exception (ErrorCall(..))
import Control.Monad
import Control.Monad.Catch
import qualified Data.List as List
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe (fromMaybe, isNothing, maybeToList)
import Data.Monoid ((<>))
import Data.String.Conversions
import qualified Data.Text as ST
import Data.Time
import Data.Typeable (Proxy(Proxy), Typeable, typeOf)
import GHC.Stack
import Lens.Micro
import Prelude hiding ((.), id)
import Text.Show.Pretty (ppShow)
import Text.XML hiding (renderText)
import qualified Text.XML
import Text.XML.Cursor
import URI.ByteString

import SAML.WebSSO.Types
import Text.XML.Iso
import Text.XML.Util

import qualified Data.Tree.NTree.TypeDefs as HS
import qualified Network.URI as HS
import qualified SAML2.Core as HS
import qualified SAML2.Core.Protocols as HS
import qualified SAML2.Profiles as HS
import qualified SAML2.XML as HS
import qualified Text.XML.HXT.DOM.TypeDefs as HS


----------------------------------------------------------------------
-- HasXML class

encode :: forall a. HasXMLRoot a => a -> LT
encode = Text.XML.renderText settings . renderToDocument
  where
    settings = def { rsNamespaces = nameSpaces (Proxy @a), rsXMLDeclaration = False }

decode :: forall m a. (HasXMLRoot a, MonadThrow m) => LT -> m a
decode = either throwM parseFromDocument . parseText def


renderToDocument :: HasXMLRoot a => a -> Document
renderToDocument = mkDocument . renderRoot


parseFromDocument :: (HasXML a, MonadThrow m) => Document -> m a
parseFromDocument = parse . fromDocument


die :: forall a b c m. (Typeable a, Show b, MonadThrow m) => Proxy a -> b -> m c
die Proxy msg = throwM . ErrorCall $
  "HasXML: could not parse " <> show (typeOf @a undefined) <> ": " <> show msg


-- TODO: perhaps we want to split this up: HasXML (for nameSpaces), and HasXMLParse, HasXMLRender,
-- and drop the assymetric, little used render function from HasXML?

class HasXML a where
  nameSpaces :: Proxy a -> [(ST, ST)]
  nameSpaces Proxy = defNameSpaces

  render :: a -> [Node]
  default render :: HasXMLRoot a => a -> [Node]
  render = (:[]) . NodeElement . renderRoot

  parse  :: MonadThrow m => Cursor -> m a

class HasXML a => HasXMLRoot a where
  renderRoot :: a -> Element


instance HasXML Document where
  parse (node -> NodeElement el) = pure $ Document defPrologue el defMiscellaneous
  parse bad = die (Proxy @Document) bad

instance HasXMLRoot Document where
  renderRoot (Document _ el _) = el


----------------------------------------------------------------------
-- util

-- | Do not use this in production!  It works, but it's slow and failures are a bit violent.
unsafeReadTime :: HasCallStack => String -> Time
unsafeReadTime s = fromMaybe (error ("decodeTime: " <> show s)) $ decodeTime s

decodeTime :: (MonadThrow m, ConvertibleStrings s String) => s -> m Time
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

renderURI :: URI -> ST
renderURI = cs . serializeURIRef'

parseURI' :: MonadThrow m => ST -> m URI  -- TODO: find a better name.  make renderURI match that name.
parseURI' = either (die (Proxy @URI)) pure . parseURI laxURIParserOptions . cs . ST.strip

-- | fmap an outer computation into an inner computation that may fail, then flip inner @n@ and
-- outer @m@.  (except for the flip, this is just 'fmap'.)
fmapFlipM :: (Monad m, Traversable n) => (a -> m b) -> n a -> m (n b)
fmapFlipM f = sequence . fmap f


----------------------------------------------------------------------
-- hack: use hsaml2 parsers and convert from SAMLProtocol instances

wrapParse :: forall (m :: * -> *) them us.
             (HasCallStack, MonadThrow m, HS.SAMLProtocol them, HasXMLRoot us, Typeable us)
          => (them -> m us) -> Cursor -> m us
wrapParse imprt cursor = either (die (Proxy @us) . (, cursor)) imprt $ HS.xmlToSAML (renderCursor cursor)

renderCursor :: HasCallStack => Cursor -> LBS
renderCursor (node -> NodeElement el) = renderLBS def $ Document defPrologue el defMiscellaneous
renderCursor bad = error $ "internal error: " <> show bad

wrapRender :: forall them us.
              (HasCallStack, HS.SAMLProtocol them, HasXMLRoot us)
           => (us -> them) -> us -> Element
wrapRender exprt = parseElement (Proxy @us) . HS.samlToXML . exprt

parseElement :: HasCallStack => Proxy a -> LBS -> Element
parseElement proxy lbs = case parseLBS def lbs of
  Right (Document _ el _) -> el
  Left msg  -> error $ show (proxy, msg)


instance HasXML     EntityDescriptor where parse      = wrapParse importEntityDescriptor
instance HasXMLRoot EntityDescriptor where renderRoot = wrapRender exportEntityDescriptor
instance HasXML     AuthnRequest     where parse      = wrapParse importAuthnRequest
instance HasXMLRoot AuthnRequest     where renderRoot = wrapRender exportAuthnRequest
instance HasXML     AuthnResponse    where parse      = wrapParse importAuthnResponse
instance HasXMLRoot AuthnResponse    where renderRoot = wrapRender exportAuthnResponse


importEntityDescriptor :: (HasCallStack, MonadThrow m) => HS.Response -> m EntityDescriptor
importEntityDescriptor = error . ppShow

exportEntityDescriptor :: HasCallStack => EntityDescriptor -> HS.Response
exportEntityDescriptor = error . ppShow


importAuthnRequest :: MonadThrow m => HS.AuthnRequest -> m AuthnRequest
importAuthnRequest req = do
  let proto = HS.requestProtocol $ HS.authnRequest req
  x0 :: ID        <- importID $ HS.protocolID proto
  x1 :: Version   <- importVersion $ HS.protocolVersion proto
  x2 :: Time      <- importTime $ HS.protocolIssueInstant proto
  x3 :: NameID    <- importRequiredIssuer $ HS.protocolIssuer proto
  x4 :: Maybe URI <- fmapFlipM importURI $ HS.protocolDestination proto

  -- TODO: make sure everything in HS.AuthnRequest that might change the interpreation of the data
  -- we know is 'Nothing'.  also do this on all other 'import*' functions.  (or should we only do
  -- this once we have our own parsers only based on stack-prism and xml-conduit?)
  pure AuthnRequest
    { _rqID           = x0
    , _rqVersion      = x1
    , _rqIssueInstant = x2
    , _rqIssuer       = x3
    , _rqDestination  = x4
    }

exportAuthnRequest :: AuthnRequest -> HS.AuthnRequest
exportAuthnRequest req = defAuthnRequest proto
  where
    proto = (defProtocolType (exportID $ req ^. rqID) (exportTime $ req ^. rqIssueInstant))
      { HS.protocolVersion = exportVersion $ req ^. rqVersion
      , HS.protocolIssuer = exportRequiredIssuer $ req ^. rqIssuer
      , HS.protocolDestination = exportURI <$> req ^. rqDestination
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


importAuthnResponse :: (HasCallStack, MonadThrow m) => HS.Response -> m AuthnResponse
importAuthnResponse rsp = do
  let rsptyp :: HS.StatusResponseType = HS.response rsp
      proto  :: HS.ProtocolType       = HS.statusProtocol rsptyp

  x0 :: ID           <- importID $ HS.protocolID proto
  x1 :: ID           <- maybe (die (Proxy @AuthnResponse)
                                   ("statusInResponseTo" :: String, HS.statusInResponseTo rsptyp))
                              (importID . cs)
                        $ HS.statusInResponseTo rsptyp
  x2 :: Version      <- importVersion $ HS.protocolVersion proto
  x3 :: Time         <- importTime $ HS.protocolIssueInstant proto
  x4 :: Maybe URI    <- fmapFlipM importURI $ HS.protocolDestination proto
  x5 :: Maybe NameID <- importOptionalIssuer $ HS.protocolIssuer proto
  x6 :: Status       <- importStatus $ HS.status rsptyp
  x7 :: [Assertion]  <- importAssertion `mapM` HS.responseAssertions rsp

  pure Response
    { _rspID           = x0
    , _rspInRespTo     = x1
    , _rspVersion      = x2
    , _rspIssueInstant = x3
    , _rspDestination  = x4
    , _rspIssuer       = x5
    , _rspStatus       = x6
    , _rspPayload      = x7
    }

exportAuthnResponse :: HasCallStack => AuthnResponse -> HS.Response
exportAuthnResponse = error . ppShow


importAssertion :: (HasCallStack, MonadThrow m) => HS.PossiblyEncrypted HS.Assertion -> m Assertion
importAssertion bad@(HS.SoEncrypted _) = die (Proxy @Assertion) bad
importAssertion (HS.NotEncrypted ass) = do
  x0 <- importVersion $ HS.assertionVersion ass
  x1 <- importID $ HS.assertionID ass
  x2 <- importTime $ HS.assertionIssueInstant ass
  x3 <- importIssuer $ HS.assertionIssuer ass
  x4 <- fmapFlipM importConditions $ HS.assertionConditions ass
  x5 <- do
    subj  <- importSubject $ HS.assertionSubject ass
    when (null $ HS.assertionStatement ass) $
      die (Proxy @Assertion) ("no statements" :: String)
    stmt:stmts <- importStatement `mapM` HS.assertionStatement ass
    pure $ SubjectAndStatements subj (stmt :| stmts)

  unless (null $ HS.assertionAdvice ass) $
    die (Proxy @Assertion) (HS.assertionAdvice ass)

  pure Assertion
    { _assVersion      = x0 :: Version
    , _assID           = x1 :: ID
    , _assIssueInstant = x2 :: Time
    , _assIssuer       = x3 :: NameID
    , _assConditions   = x4 :: Maybe Conditions
    , _assContents     = x5 :: SubjectAndStatements
    }


importSubject :: (HasCallStack, MonadThrow m) => HS.Subject -> m Subject
importSubject (HS.Subject Nothing _) = die (Proxy @Subject) ("need to provide a subject" :: String)
importSubject (HS.Subject (Just (HS.SoEncrypted _)) _) = die (Proxy @Subject) ("encrypted subjects not supported" :: String)
importSubject (HS.Subject (Just (HS.NotEncrypted sid)) scs) = case sid of
  HS.IdentifierName HS.NameID
    { HS.nameBaseID = HS.BaseID _ _ (SubjectID . cs -> uid)
    , HS.nameIDFormat = HS.Identified HS.NameIDFormatPersistent
    , HS.nameSPProvidedID = Nothing
    } -> Subject uid <$> importSubjectConfirmation uid `mapM` scs
  bad -> die (Proxy @Subject) ("unsupported subject identifier: " <> show bad)

importSubjectConfirmation :: (HasCallStack, MonadThrow m) => SubjectID -> HS.SubjectConfirmation -> m SubjectConfirmation
importSubjectConfirmation = go
  where
    go _ (HS.SubjectConfirmation meth _ _) | meth /= HS.Identified HS.ConfirmationMethodBearer
      = die (Proxy @SubjectConfirmation) ("unsupported confirmation method: " <> show meth)
    go (SubjectID uid) (HS.SubjectConfirmation _ (Just (HS.NotEncrypted (HS.IdentifierName (HS.NameID _ _ (Just (cs -> uid')))))) _) | uid /= uid'
      = die (Proxy @SubjectConfirmation) ("uid mismatch: " <> show (uid, uid'))
    go _ (HS.SubjectConfirmation _ (Just bad) _)
      = die (Proxy @SubjectConfirmation) ("unsupported identifier: " <> show bad)
    go _ (HS.SubjectConfirmation _ _ confdata)
      = SubjectConfirmation SubjectConfirmationMethodBearer <$> importSubjectConfirmationData `mapM` maybeToList confdata

importSubjectConfirmationData :: (HasCallStack, MonadThrow m) => HS.SubjectConfirmationData -> m SubjectConfirmationData
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

importIP :: (HasCallStack, MonadThrow m) => HS.IP -> m IP
importIP = pure . IP . cs


importConditions :: (HasCallStack, MonadThrow m) => HS.Conditions -> m Conditions
importConditions conds = do
  x0 <- fmapFlipM importTime $ HS.conditionsNotBefore conds
  x1 <- fmapFlipM importTime $ HS.conditionsNotOnOrAfter conds
  let x2 = HS.OneTimeUse `elem` HS.conditions conds

  unless (HS.conditions conds `notElem` [[], [HS.OneTimeUse]]) $
    die (Proxy @Conditions) ("unsupported conditions" :: String, HS.conditions conds)

  pure Conditions
    { _condNotBefore    = x0
    , _condNotOnOrAfter = x1
    , _condOneTimeUse   = x2
    }


importStatement :: (HasCallStack, MonadThrow m)
                => HS.Statement -> m Statement
importStatement (HS.StatementAttribute st) =
  AttributeStatement <$> (importAttribute `mapM` HS.attributeStatement st)
importStatement (HS.StatementAuthn st) = do
  x0 <- importTime $ HS.authnStatementInstant st
  let x1 = cs <$> HS.authnStatementSessionIndex st
  pure AuthnStatement
    { _astAuthnInstant        = x0 :: Time
    , _astSessionIndex        = x1 :: Maybe ST
    , _astSessionNotOnOrAfter = Nothing
    , _astSubjectLocality     = Nothing
    }
importStatement bad = die (Proxy @Statement) bad


importAttribute :: (HasCallStack, MonadThrow m)
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

importAttributeValue :: (HasCallStack, MonadThrow m) => HS.Nodes -> m AttributeValue
importAttributeValue [HS.NTree (HS.XText txt) []] = pure . AttributeValueText $ cs txt
importAttributeValue bad = die (Proxy @AttributeValue) bad


importID :: (HasCallStack, MonadThrow m) => HS.ID -> m ID
importID = pure . ID . cs

exportID :: HasCallStack => ID -> HS.ID
exportID (ID t) = cs t

importNameID :: (HasCallStack, MonadThrow m) => HS.NameID -> m NameID
importNameID (HS.NameID (HS.BaseID Nothing Nothing i) (HS.Identified HS.NameIDFormatEntity) Nothing)
  = pure . NameID . cs $ i
importNameID bad
  = die (Proxy @NameID) bad

exportNameID :: HasCallStack => NameID -> HS.NameID
exportNameID (NameID i) = HS.NameID
  { HS.nameBaseID = HS.BaseID Nothing Nothing (cs i)
  , HS.nameIDFormat = HS.Identified HS.NameIDFormatEntity
  , HS.nameSPProvidedID = Nothing
  }

importVersion :: (HasCallStack, MonadThrow m) => HS.SAMLVersion -> m Version
importVersion HS.SAML20 = pure Version_2_0
importVersion bad = die (Proxy @Version) bad

exportVersion :: HasCallStack => Version -> HS.SAMLVersion
exportVersion Version_2_0 = HS.SAML20

importTime :: (HasCallStack, MonadThrow m) => HS.DateTime -> m Time
importTime = pure . Time

exportTime :: HasCallStack => Time -> HS.DateTime
exportTime = fromTime

importURI :: (HasCallStack, MonadThrow m) => HS.URI -> m URI
importURI uri = parseURI' . cs $ HS.uriToString id uri mempty

exportURI :: HasCallStack => URI -> HS.URI
exportURI uri = fromMaybe err . HS.parseURIReference . cs . renderURI $ uri
  where err = error $ "internal error: " <> show uri

importStatus :: (HasCallStack, MonadThrow m) => HS.Status -> m Status
importStatus (HS.Status (HS.StatusCode HS.StatusSuccess []) Nothing Nothing) = pure StatusSuccess
importStatus status = pure . StatusFailure . cs . show $ status

exportStatus :: HasCallStack => Status -> HS.Status
exportStatus StatusSuccess = HS.Status (HS.StatusCode HS.StatusSuccess []) Nothing Nothing
exportStatus bad = error $ "not implemented: " <> show bad

importIssuer :: (HasCallStack, MonadThrow m) => HS.Issuer -> m NameID
importIssuer = importNameID . HS.issuer

exportIssuer :: HasCallStack => NameID -> HS.Issuer
exportIssuer = HS.Issuer . exportNameID

importOptionalIssuer :: (HasCallStack, MonadThrow m) => Maybe HS.Issuer -> m (Maybe NameID)
importOptionalIssuer = fmapFlipM importIssuer

exportOptionalIssuer :: HasCallStack => Maybe NameID -> Maybe HS.Issuer
exportOptionalIssuer = fmap exportIssuer

importRequiredIssuer :: (HasCallStack, MonadThrow m) => Maybe HS.Issuer -> m NameID
importRequiredIssuer = maybe (die (Proxy @AuthnRequest) ("no issuer id" :: String)) importIssuer

exportRequiredIssuer :: HasCallStack => NameID -> Maybe HS.Issuer
exportRequiredIssuer = Just . exportIssuer
