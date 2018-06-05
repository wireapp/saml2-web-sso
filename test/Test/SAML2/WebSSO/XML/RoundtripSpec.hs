{-# OPTIONS_GHC -Wno-unused-binds #-}

module Test.SAML2.WebSSO.XML.RoundtripSpec (spec) where

import Arbitrary
import Data.List.NonEmpty
import Data.String.Conversions
import Hedgehog
import SAML2.WebSSO
import Test.Hspec
import Text.XML
import Util

import qualified Data.Map as Map
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range


spec :: Spec
spec = hedgehog $ checkParallel $$(discover)

mkprop :: forall a. (Eq a, Show a, HasXML a) => Gen a -> Property
mkprop gen = property $ forAll gen >>= \v -> tripping v render (parse @a @(Either String))


prop_tripNameID :: Property
prop_tripNameID = mkprop genNameID

{-- TODO: enable

_prop_tripEntityDescriptor :: Property
_prop_tripEntityDescriptor = mkprop genEntityDescriptor

-- TODO: enable
_prop_tripAuthnRequest :: Property
_prop_tripAuthnRequest = mkprop genAuthnRequest

-- TODO: enable
_prop_tripAuthnResponse :: Property
_prop_tripAuthnResponse = mkprop (Gen.prune genAuthnResponse)
  -- without the 'prune', this triggers https://github.com/hedgehogqa/haskell-hedgehog/issues/174
-}


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
    NameIDFEntity uri -> pure $ entityNameID uri
    _ -> either (error . show) pure =<<
         (mkNameID unid <$> qualifier <*> qualifier <*> qualifier)
  where
    qualifier = Gen.maybe . genNiceText $ Range.exponential 1 2000

genUnqualifiedNameID :: Gen UnqualifiedNameID
genUnqualifiedNameID = Gen.choice
  [ NameIDFUnspecified <$> genNiceText (Range.exponential 1 2000)
  , NameIDFEmail       <$> genNiceText (Range.exponential 1 2000)
  , NameIDFX509        <$> genNiceText (Range.exponential 1 2000)
  , NameIDFWindows     <$> genNiceText (Range.exponential 1 2000)
  , NameIDFKerberos    <$> genNiceText (Range.exponential 1 2000)
  , NameIDFEntity      <$> genURI' (Just (Range.exponential 1 1024))
  , NameIDFPersistent  <$> genNiceText (Range.exponential 1 1024)
  , NameIDFTransient   <$> genNiceText (Range.exponential 1 2000)
  ]

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
