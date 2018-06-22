{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module SAML2.WebSSO.Test.Arbitrary where

import Data.List.NonEmpty
import Data.String.Conversions
import Hedgehog
import SAML2.WebSSO
import Test.QuickCheck (Arbitrary(arbitrary))
import Text.XML
import URI.ByteString
import URI.ByteString.QQ

import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Gen.QuickCheck as THQ
import qualified Hedgehog.Range as Range
import qualified Test.QuickCheck.Hedgehog as TQH


genVersion :: Gen Version
genVersion = Gen.enumBounded

genURI :: Gen URI
genURI = genURI' Nothing

-- | arbitrary 'URI' with restricted length.
--
-- TODO: uri-bytestring has Arbitrary instances, but they are internal as of now.
-- https://github.com/Soostone/uri-bytestring/issues/45
genURI' :: Maybe (Range Int) -> Gen URI
genURI' _ = pure [uri|http://wire.com/|]

-- | pick N words from a dictionary of popular estonian first names.  this should yield enough
-- entropy, but is much nicer to read.
--
-- (quickcheck has something like this as well.)
genNiceText :: Range Int -> Gen ST
genNiceText rng = ST.unwords <$> Gen.list rng word
  where
    -- popular estonian first names.
    word = Gen.element
      [ "aiandama", "aitama", "aitamah", "aleksander", "andres", "andrus", "anu", "arri", "aruka"
      , "aytama", "aytamah", "betti", "daggi", "dagi", "dagmara", "diana", "edenema", "eduk"
      , "eliisabet", "elisabet", "elsbet", "elts", "etti", "etty", "hele", "hendrik", "jaak"
      , "juku", "juri", "kaisa", "kaja", "katariina", "koit", "leena", "lenni", "liisi", "lilli"
      , "loviise", "maarja", "marika", "nikolai", "rina", "sandra", "sula", "taevas", "taniel"
      , "tonis", "ulli", "urmi", "vicenc", "anna", "eluta", "hillar", "jaagup", "jaan", "janek"
      , "jannis", "jens", "johan", "johanna", "juhan", "katharina", "kati", "katja", "krista"
      , "kristian", "kristina", "kristjan", "krists", "laura", "leks", "liisa", "marga"
      , "margarete", "mari", "maria", "marye", "mati", "matt", "mihkel", "mikk", "olli", "olly"
      , "peet", "peeter", "pinja", "reet", "riki", "riks", "rolli", "toomas"
      ]

genNiceWord :: Gen ST
genNiceWord = genNiceText (Range.singleton 1)


genConfig :: Gen extra -> Gen (Config extra)
genConfig genextra = do
  _cfgVersion    <- genVersion
  _cfgLogLevel   <- Gen.enumBounded
  _cfgSPHost     <- cs <$> genNiceWord
  _cfgSPPort     <- Gen.int (Range.linear 1 9999)
  _cfgSPAppURI   <- genURI
  _cfgSPSsoURI   <- genURI
  _cfgContacts   <- (:|) <$> genSPContactPerson <*> Gen.list (Range.linear 0 3) genSPContactPerson
  _cfgIdps       <- pure mempty
  _cfgExtraInfo  <- Gen.maybe genextra
  pure Config{..}

genSPContactPerson :: Gen SPContactPerson
genSPContactPerson = SPContactPerson
  <$> genNiceWord
  <*> genNiceWord
  <*> genNiceWord
  <*> genURI
  <*> genNiceWord


instance Arbitrary UserRef where
  arbitrary = UserRef <$> arbitrary <*> arbitrary


genEntityDescriptor :: Gen EntityDescriptor
genEntityDescriptor = EntityDescriptor
  <$> genNiceWord
  <*> Gen.maybe genID
  <*> Gen.maybe genTime
  <*> Gen.maybe genDuration
  <*> Gen.list (Range.linear 0 8) genEntityDescriptionExtension
  <*> Gen.list (Range.linear 0 8) genRole

genEntityDescriptionExtension :: Gen EntityDescriptionExtension
genEntityDescriptionExtension = Gen.choice
  [ EntityDescriptionDigestMethod <$> genURI
  , EntityDescriptionSigningMethod <$> genURI
  ]

genRole :: Gen Role
genRole = Gen.choice
  [ RoleRoleDescriptor <$> genRoleDescriptor
  , RoleIDPSSODescriptor <$> genIDPSSODescriptor
  , RoleSPSSODescriptor <$> genSPSSODescriptor
  ]

genRoleDescriptor :: Gen RoleDescriptor
genRoleDescriptor = do
  _rssoID                         <- Gen.maybe genID
  _rssoValidUntil                 <- Gen.maybe genTime
  _rssoCacheDuration              <- Gen.maybe genDuration
  _rssoProtocolSupportEnumeration <- genNonEmpty (Range.linear 1 5) genNiceWord
  _rssoErrorURL                   <- Gen.maybe genURI
  _rssoKeyDescriptors             <- Gen.list (Range.linear 0 5) genKeyDescriptor
  pure RoleDescriptor {..}

genKeyDescriptor :: Gen KeyDescriptor
genKeyDescriptor = KeyDescriptor
  <$> Gen.maybe Gen.enumBounded
  <*> pure ()
  <*> pure ()

genIDPSSODescriptor :: Gen IDPSSODescriptor
genIDPSSODescriptor = do
  _idpWantAuthnRequestsSigned  <- Gen.bool
  _idpSingleSignOnService      <- genNonEmpty (Range.linear 0 5) genEndPointNoRespLoc
  _idNameIDMappingService      <- Gen.list (Range.linear 0 5) genEndPointNoRespLoc
  _idAssertionIDRequestService <- Gen.list (Range.linear 0 5) genEndPointAllowRespLoc
  _idAttributeProfile          <- Gen.list (Range.linear 0 5) genURI

  pure IDPSSODescriptor {..}

genEndPointNoRespLoc :: Gen EndPointNoRespLoc
genEndPointNoRespLoc = EndPoint <$> genNiceWord <*> genURI <*> pure ()

genEndPointAllowRespLoc :: Gen EndPointAllowRespLoc
genEndPointAllowRespLoc = EndPoint <$> genNiceWord <*> genURI <*> Gen.maybe genURI

genSPSSODescriptor :: Gen SPSSODescriptor
genSPSSODescriptor = pure SPSSODescriptor


genAuthnRequest :: Gen AuthnRequest
genAuthnRequest = AuthnRequest <$> genID <*> genVersion <*> genTime <*> genIssuer

genTime :: Gen Time
genTime = pure $ unsafeReadTime "2013-03-18T07:33:56Z"

genDuration :: Gen Duration
genDuration = pure Duration

genID :: Gen (ID a)
genID = ID <$> genNiceText (Range.singleton 2)

genIssuer :: Gen Issuer
genIssuer = Issuer <$> genURI

genNameID :: Gen NameID
genNameID = do
  unid <- genUnqualifiedNameID
  case unid of
    NameIDFEntity enturi -> pure $ entityNameID enturi
    _ -> either (error . show) pure =<<
         (mkNameID unid <$> qualifier <*> qualifier <*> qualifier)
  where
    qualifier = Gen.maybe . genNiceText $ Range.exponential 1 100

genUnqualifiedNameID :: Gen UnqualifiedNameID
genUnqualifiedNameID = Gen.choice
  [ NameIDFUnspecified <$> mktxt 2000
  , NameIDFEmail       <$> mktxt 2000
  , NameIDFX509        <$> mktxt 2000
  , NameIDFWindows     <$> mktxt 2000
  , NameIDFKerberos    <$> mktxt 2000
  , NameIDFEntity      <$> genURI' (Just (Range.linear 1 1024))
  , NameIDFPersistent  <$> mktxt 1024
  , NameIDFTransient   <$> mktxt 2000
  ]
  where
    mktxt charlen = cs <$> Gen.text (Range.linear 1 charlen) Gen.alpha

genNonEmpty :: Range Int -> Gen a -> Gen (NonEmpty a)
genNonEmpty rng gen = (:|) <$> gen <*> Gen.list rng gen

genStatus :: Gen Status
genStatus = undefined  -- Gen.enumBounded

genAuthnResponse :: Gen AuthnResponse
genAuthnResponse = genResponse $ Gen.list (Range.linear 0 100) genAssertion

genResponse :: forall payload. Gen payload -> Gen (Response payload)
genResponse genPayload = do
  _rspID           <- genID
  _rspInRespTo     <- Gen.maybe genID
  _rspVersion      <- genVersion
  _rspIssueInstant <- genTime
  _rspDestination  <- Gen.maybe genURI
  _rspIssuer       <- Gen.maybe genIssuer
  _rspStatus       <- genStatus
  _rspPayload      <- Gen.small genPayload

  pure Response {..}

genAssertion :: Gen Assertion
genAssertion = do
  _assVersion      <- genVersion
  _assID           <- genID
  _assIssueInstant <- genTime
  _assIssuer       <- genIssuer
  _assConditions   <- Gen.maybe genConditions
  _assContents     <- genSubjectAndStatements

  pure Assertion {..}

genConditions :: Gen Conditions
genConditions = Conditions
  <$> Gen.maybe genTime
  <*> Gen.maybe genTime
  <*> Gen.bool
  <*> Gen.maybe (genNonEmpty (Range.linear 0 2) genURI)

genSubjectAndStatements :: Gen SubjectAndStatements
genSubjectAndStatements = SubjectAndStatements <$> genSubject <*> genNonEmpty (Range.linear 0 15) genStatement

genSubject :: Gen Subject
genSubject = Subject
  <$> genNameID
  <*> Gen.list (Range.linear 0 8) genSubjectConfirmation

genSubjectConfirmation :: Gen SubjectConfirmation
genSubjectConfirmation = SubjectConfirmation
  <$> genSubjectConfirmationMethod
  <*> Gen.list (Range.linear 1 8) genSubjectConfirmationData

genSubjectConfirmationMethod :: Gen SubjectConfirmationMethod
genSubjectConfirmationMethod = Gen.enumBounded

genSubjectConfirmationData :: Gen SubjectConfirmationData
genSubjectConfirmationData = do
  _scdNotBefore    <- Gen.maybe genTime
  _scdNotOnOrAfter <- genTime
  _scdRecipient    <- genURI
  _scdInResponseTo <- Gen.maybe genID
  _scdAddress      <- Gen.maybe genIP

  pure SubjectConfirmationData {..}

genIP :: Gen IP
genIP = IP <$> (genNiceText $ Range.linear 1 10)

genStatement :: Gen Statement
genStatement = Gen.choice
  [ do
      _astAuthnInstant        <- genTime
      _astSessionIndex        <- Gen.maybe genNiceWord
      _astSessionNotOnOrAfter <- Gen.maybe genTime
      _astSubjectLocality     <- Gen.maybe genLocality
      pure AuthnStatement {..}

--  , AttributeStatement <$> Gen.list (Range.linear 1 15) genAttribute
  ]

genLocality :: Gen Locality
genLocality = Locality <$> Gen.maybe genNiceWord <*> Gen.maybe genNiceWord

genAttribute :: Gen Attribute
genAttribute = Gen.choice
  [ Attribute
    <$> genNiceWord
    <*> Gen.maybe genURI
    <*> Gen.maybe genNiceWord
    <*> Gen.list (Range.linear 0 8) (Gen.small genAttributeValue)
  ]

genAttributeValue :: Gen AttributeValue
genAttributeValue = undefined

genXMLNode :: Gen Node
genXMLNode = Gen.choice
  [ NodeElement <$> genXMLElement
  , NodeInstruction <$> genXMLInstruction
  , NodeContent <$> genNiceText (Range.linear 0 100)
  , NodeComment <$> genNiceText (Range.linear 0 100)
  ]

genXMLElement :: Gen Element
genXMLElement = Element
  <$> genXMLName
  <*> genXMLAttrs
  <*> Gen.list (Range.linear 1 10) (Gen.small genXMLNode)

genXMLName :: Gen Name
genXMLName = Name
  <$> genNiceText (Range.linear 1 2)
  <*> Gen.maybe (genNiceText (Range.linear 1 3))
  <*> Gen.maybe genNiceWord

genXMLAttrs :: Gen (Map.Map Name ST)
genXMLAttrs = Map.fromList <$> Gen.list (Range.linear 1 100) genXMLAttr

genXMLAttr :: Gen (Name, ST)
genXMLAttr = (,) <$> genXMLName <*> genNiceWord

genXMLInstruction :: Gen Instruction
genXMLInstruction = Instruction <$> genNiceWord <*> genNiceWord


-- TODO: the following should be TH-generated entirely (take all declarations matching '^gen' and
-- turn the resp. types into Arbitrary instances).

instance Arbitrary Assertion where
  arbitrary = TQH.hedgehog genAssertion

instance Arbitrary Attribute where
  arbitrary = TQH.hedgehog genAttribute

instance Arbitrary AttributeValue where
  arbitrary = TQH.hedgehog genAttributeValue

instance Arbitrary AuthnRequest where
  arbitrary = TQH.hedgehog genAuthnRequest

instance Arbitrary Conditions where
  arbitrary = TQH.hedgehog genConditions

instance Arbitrary extra => Arbitrary (Config extra) where
  arbitrary = TQH.hedgehog (genConfig $ THQ.quickcheck arbitrary)

instance Arbitrary Duration where
  arbitrary = TQH.hedgehog genDuration

instance Arbitrary EndPointAllowRespLoc where
  arbitrary = TQH.hedgehog genEndPointAllowRespLoc

instance Arbitrary EndPointNoRespLoc where
  arbitrary = TQH.hedgehog genEndPointNoRespLoc

instance Arbitrary Issuer where
  arbitrary = TQH.hedgehog genIssuer

instance Arbitrary KeyDescriptor where
  arbitrary = TQH.hedgehog genKeyDescriptor

instance Arbitrary Locality where
  arbitrary = TQH.hedgehog genLocality

instance Arbitrary NameID where
  arbitrary = TQH.hedgehog genNameID

instance Arbitrary a => Arbitrary (NonEmpty a) where
  arbitrary = TQH.hedgehog (genNonEmpty (Range.linear 1 100) $ THQ.quickcheck arbitrary)

instance Arbitrary payload => Arbitrary (Response payload) where
  arbitrary = TQH.hedgehog (genResponse $ THQ.quickcheck arbitrary)

instance Arbitrary Role where
  arbitrary = TQH.hedgehog genRole

instance Arbitrary SubjectConfirmationData where
  arbitrary = TQH.hedgehog genSubjectConfirmationData

instance Arbitrary SubjectConfirmationMethod where
  arbitrary = TQH.hedgehog genSubjectConfirmationMethod

instance Arbitrary Time where
  arbitrary = TQH.hedgehog genTime

instance Arbitrary UnqualifiedNameID where
  arbitrary = TQH.hedgehog genUnqualifiedNameID

instance Arbitrary URI where
  arbitrary = TQH.hedgehog genURI

instance Arbitrary Version where
  arbitrary = TQH.hedgehog genVersion
