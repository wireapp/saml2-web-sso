{-# OPTIONS_GHC -Wno-unused-binds #-}

module Test.SAML2.WebSSO.XML.RoundtripSpec (spec) where

import Arbitrary
import Data.List.NonEmpty
import Data.String.Conversions
import Hedgehog
import SAML2.WebSSO
import Test.Hspec
import Text.XML
import URI.ByteString
import Util

import qualified Data.Map as Map
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range


spec :: Spec
spec = hedgehog $ checkParallel $$(discover)

mkprop :: (Eq a, Show a, HasXMLRoot a) => Gen a -> Property
mkprop gen = property $ forAll gen >>= \v -> tripping v encode (decode @(Either String))


-- TODO: enable
-- _prop_tripEntityDescriptor :: Property
-- _prop_tripEntityDescriptor = mkprop genEntityDescriptor

-- TODO: enable
_prop_tripAuthnRequest :: Property
_prop_tripAuthnRequest = mkprop genAuthnRequest

-- TODO: enable
_prop_tripAuthnResponse :: Property
_prop_tripAuthnResponse = mkprop (Gen.prune genAuthnResponse)
  -- without the 'prune', this triggers https://github.com/hedgehogqa/haskell-hedgehog/issues/174


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
  x0 <- Gen.maybe genID
  x1 <- Gen.maybe genTime
  x2 <- Gen.maybe genDuration
  x3 <- genNonEmpty (Range.linear 1 5) genNiceWord
  x4 <- Gen.maybe genURI
  x7 <- Gen.list (Range.linear 0 5) genKeyDescriptor

  pure RoleDescriptor
    { _rssoID                         = x0
    , _rssoValidUntil                 = x1
    , _rssoCacheDuration              = x2
    , _rssoProtocolSupportEnumeration = x3
    , _rssoErrorURL                   = x4
    , _rssoKeyDescriptors             = x7
    }

genKeyDescriptor :: Gen KeyDescriptor
genKeyDescriptor = KeyDescriptor
  <$> Gen.maybe Gen.enumBounded
  <*> pure ()
  <*> pure ()

genIDPSSODescriptor :: Gen IDPSSODescriptor
genIDPSSODescriptor = do
  x0 <- Gen.bool
  x1 <- genNonEmpty (Range.linear 0 5) genEndPointNoRespLoc
  x2 <- Gen.list (Range.linear 0 5) genEndPointNoRespLoc
  x3 <- Gen.list (Range.linear 0 5) genEndPointAllowRespLoc
  x4 <- Gen.list (Range.linear 0 5) genURI

  pure IDPSSODescriptor
    { _idpWantAuthnRequestsSigned  = x0
    , _idpSingleSignOnService      = x1
    , _idNameIDMappingService      = x2
    , _idAssertionIDRequestService = x3
    , _idAttributeProfile          = x4
    }

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
genIssuer = Issuer <$> genNameID

-- | TODO: what else do we need here?
genNameID :: Gen NameID
genNameID = Gen.choice [entityNameID <$> genURI, opaqueNameID <$> (genNiceText $ Range.linear 1 10)]

genNonEmpty :: Range Int -> Gen a -> Gen (NonEmpty a)
genNonEmpty rng gen = (:|) <$> gen <*> Gen.list rng gen

genStatus :: Gen Status
genStatus = undefined  -- Gen.enumBounded

genAuthnResponse :: Gen AuthnResponse
genAuthnResponse = genResponse $ Gen.list (Range.linear 0 100) genAssertion

genResponse :: forall payload. Gen payload -> Gen (Response payload)
genResponse genPayload = do
  x0 <- genID
  x1 <- Gen.maybe genID
  x2 <- genVersion
  x3 <- genTime
  x4 <- Gen.maybe genURI
  x5 <- Gen.maybe genIssuer
  x7 <- genStatus
  x8 <- Gen.small genPayload

  pure Response
    { _rspID           = x0
    , _rspInRespTo     = x1
    , _rspVersion      = x2 :: Version
    , _rspIssueInstant = x3 :: Time
    , _rspDestination  = x4 :: Maybe URI
    , _rspIssuer       = x5 :: Maybe Issuer
    , _rspStatus       = x7 :: Status
    , _rspPayload      = x8 :: payload
    }

genAssertion :: Gen Assertion
genAssertion = do
  x0 <- genVersion
  x1 <- genID
  x2 <- genTime
  x3 <- genIssuer
  x5 <- Gen.maybe genConditions
  x6 <- genSubjectAndStatements

  pure Assertion
    { _assVersion       = x0 :: Version
    , _assID            = x1
    , _assIssueInstant  = x2 :: Time
    , _assIssuer        = x3 :: Issuer
    , _assConditions    = x5 :: Maybe Conditions
    , _assContents      = x6 :: SubjectAndStatements
    }

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
  x0 <- Gen.maybe genTime
  x1 <- genTime
  x2 <- genURI
  x3 <- Gen.maybe genID
  x4 <- Gen.maybe genIP

  pure SubjectConfirmationData
    { _scdNotBefore    = x0
    , _scdNotOnOrAfter = x1
    , _scdRecipient    = x2
    , _scdInResponseTo = x3
    , _scdAddress      = x4
    }

genIP :: Gen IP
genIP = IP <$> (genNiceText $ Range.linear 1 10)

genStatement :: Gen Statement
genStatement = Gen.choice
  [ do
      x0 <- genTime
      x1 <- Gen.maybe genNiceWord
      x2 <- Gen.maybe genTime
      x3 <- Gen.maybe genLocality

      pure AuthnStatement
        { _astAuthnInstant        = x0 :: Time
        , _astSessionIndex        = x1 :: Maybe ST
        , _astSessionNotOnOrAfter = x2 :: Maybe Time
        , _astSubjectLocality     = x3 :: Maybe Locality
        }

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
