{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeApplications    #-}

{-# OPTIONS_GHC -Wno-unused-binds #-}

-- | FUTUREWORK: should we use <https://github.com/qfpl/tasty-hedgehog> to integrate this in "Main"?
module Test.SAML.WebSSO.XML.Roundtrip (tests) where

import Data.List.NonEmpty
import qualified Data.Map as Map
import Data.String.Conversions
import qualified Data.Text as ST
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import SAML.WebSSO
import Test.Tasty
import Test.Util
import Text.XML
import URI.ByteString


tests :: TestTree
tests = hedgehog $ do
  recheck (Size 0) (Seed 3728376268721921158 (-22573230863195311)) prop_tripConditions
  checkParallel $$(discover)

mkprop :: (Eq a, Show a, HasXMLRoot a) => Gen a -> Property
mkprop gen = property $ forAll gen >>= \v -> tripping v encode (decode @Maybe)


_prop_tripEntityDescriptor :: Property
_prop_tripEntityDescriptor = mkprop genEntityDescriptor

prop_tripAuthnRequest :: Property
prop_tripAuthnRequest = mkprop genAuthnRequest

_prop_tripAuthnResponse :: Property
_prop_tripAuthnResponse = mkprop (Gen.prune genAuthnResponse)
  -- without the 'prune', this triggers https://github.com/hedgehogqa/haskell-hedgehog/issues/174

_prop_tripAssertion :: Property
_prop_tripAssertion = mkprop (Gen.prune genAssertion)

prop_tripSubject :: Property
prop_tripSubject = mkprop (Gen.prune genSubject)

prop_tripConditions :: Property
prop_tripConditions = mkprop (Gen.prune genConditions)

-- prop_tripStatement :: Property
-- prop_tripStatement = mkprop genStatement


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
  x6 <- Gen.maybe (Gen.small genXMLElement)
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
  x5 <- Gen.list (Range.linear 0 5) (Gen.small genXMLElement)

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
genAuthnRequest = AuthnRequest <$> genID <*> genVersion <*> genTime <*> genURI <*> pure Nothing

genTime :: Gen Time
genTime = pure $ unsafeReadTime "2013-03-18T07:33:56Z"

genDuration :: Gen Duration
genDuration = pure Duration

genID :: Gen ID
genID = ID <$> genNiceText (Range.singleton 2)

-- | pick N words from a dictionary of popular estonian first names.  this should yield enough
-- entropy, but is much nicer to read.
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

genNonEmpty :: Range Int -> Gen a -> Gen (NonEmpty a)
genNonEmpty rng gen = (:|) <$> gen <*> Gen.list rng gen

genVersion :: Gen Version
genVersion = Gen.enumBounded

genStatus :: Gen Status
genStatus = Gen.enumBounded

genURI :: Gen URI
genURI = either (error . show) pure $ parseURI' "http://wire.com/"

genAuthnResponse :: Gen AuthnResponse
genAuthnResponse = genResponse $ Gen.list (Range.linear 0 100) genAssertion

genResponse :: forall payload. Gen payload -> Gen (Response payload)
genResponse genPayload = do
  x0 <- genID
  x1 <- genID
  x2 <- genVersion
  x3 <- genTime
  x4 <- Gen.maybe genURI
  x5 <- Gen.maybe genURI
  x7 <- genStatus
  x8 <- Gen.small genPayload

  pure Response
    { _rspID           = x0 :: ID
    , _rspInRespTo     = x1 :: ID
    , _rspVersion      = x2 :: Version
    , _rspIssueInstant = x3 :: Time
    , _rspDestination  = x4 :: Maybe URI
    , _rspIssuer       = x5 :: Maybe URI
    , _rspStatus       = x7 :: Status
    , _rspAssertion    = x8 :: payload
    }

genAssertion :: Gen Assertion
genAssertion = do
  x0 <- genVersion
  x1 <- genID
  x2 <- genTime
  x3 <- genURI
  x5 <- genConditions
  x6 <- genSubjectAndStatements

  pure Assertion
    { _assVersion       = x0 :: Version
    , _assID            = x1 :: ID
    , _assIssueInstant  = x2 :: Time
    , _assIssuer        = x3 :: URI
    , _assConditions    = x5 :: Conditions
    , _assContents      = x6 :: SubjectAndStatements
    }

genConditions :: Gen Conditions
genConditions = Conditions
  <$> Gen.maybe genTime
  <*> Gen.maybe genTime
  <*> Gen.bool

genSubjectAndStatements :: Gen SubjectAndStatements
genSubjectAndStatements = do
  msub <- Gen.choice [Right <$> genSubject, Left <$> genStatement]
  sts  <- Gen.list (Range.linear 1 15) genStatement
  case (msub, sts) of
    (Right sub, _:_) -> pure $ SubjectAndStatements sub sts
    (Right sub, [])  -> pure $ SubjectOnly sub
    (Left st, _)     -> pure $ StatementsOnly (st : sts)

genSubject :: Gen Subject
genSubject = Subject
  <$> Gen.maybe genSubjectID
  <*> Gen.list (Range.linear 0 8) genSubjectConfirmation

genSubjectID :: Gen SubjectID
genSubjectID = Gen.choice
  [ SubjectBaseID . BaseID <$> genNiceWord
  , SubjectNameID . NameID <$> genNiceWord
  ]

genSubjectConfirmation :: Gen SubjectConfirmation
genSubjectConfirmation = SubjectConfirmation
  <$> genNiceWord
  <*> Gen.maybe genSubjectID
  <*> Gen.list (Range.linear 1 8) genSubjectConfirmationData

genSubjectConfirmationData :: Gen SubjectConfirmationData
genSubjectConfirmationData = do
  x0 <- Gen.maybe genTime
  x1 <- Gen.maybe genTime
  x2 <- Gen.maybe genURI
  x3 <- Gen.maybe genID
  x4 <- Gen.maybe (genNiceText $ Range.linear 1 10)
  x5 <- Gen.list (Range.linear 1 3) (Gen.small genXMLElement)

  pure SubjectConfirmationData
    { _scdNotBefore    = x0
    , _scdNotOnOrAfter = x1
    , _scdRecipient    = x2
    , _scdInResponseTo = x3
    , _scdAddress      = x4
    }

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
    <*> Gen.maybe genNiceWord
    <*> Gen.maybe genNiceWord
    <*> Gen.list (Range.linear 0 8) (Gen.small genXMLElement)
  ]

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
