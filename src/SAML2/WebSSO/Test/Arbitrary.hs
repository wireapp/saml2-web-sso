{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module SAML2.WebSSO.Test.Arbitrary where

import Data.List.NonEmpty as NL
import Data.Maybe (catMaybes)
import Data.String.Conversions
import Hedgehog
import SAML2.WebSSO
import Test.QuickCheck (Arbitrary(arbitrary, shrink))
import Test.QuickCheck.Instances ()
import Text.XML
import URI.ByteString
import URI.ByteString.QQ

import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Data.UUID as UUID
import qualified Data.X509 as X509
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Gen.QuickCheck as THQ
import qualified Hedgehog.Range as Range
import qualified Test.QuickCheck.Hedgehog as TQH
import qualified Text.XML.DSig as DSig


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

genSPContactPerson :: Gen ContactPerson
genSPContactPerson = ContactPerson
  <$> Gen.enumBounded
  <*> Gen.maybe genNiceWord
  <*> Gen.maybe genNiceWord
  <*> Gen.maybe genNiceWord
  <*> Gen.maybe genURI
  <*> Gen.maybe genNiceWord


instance Arbitrary UserRef where
  arbitrary = UserRef <$> arbitrary <*> arbitrary


genIdPMetadata :: Gen IdPMetadata
genIdPMetadata = IdPMetadata
  <$> genIssuer
  <*> genURI
  <*> genX509SignedCertificate
  <*> (NL.fromList <$> Gen.list (Range.linear 1 3) genX509SignedCertificate)

genX509SignedCertificate :: Gen X509.SignedCertificate
genX509SignedCertificate = either (error . show) pure $ DSig.parseKeyInfo "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk</X509Certificate></X509Data></KeyInfo>"

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

genXMLDocument :: Gen Document
genXMLDocument = Document (Prologue [] Nothing []) <$> genXMLElement <*> pure []

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
  <$> genNiceWord
  <*> Gen.maybe genNiceWord
  <*> pure Nothing -- @Gen.maybe genNiceWord@, but in documents that use the same prefix for two
                   -- different spaces, this breaks the test suite.  (FUTUREWORK: arguably the
                   -- parser libraries (either HXT or xml-conduit) should catch this and throw an
                   -- error.  current behavior is unspecified result of the name space lookup.)

genXMLAttrs :: Gen (Map.Map Name ST)
genXMLAttrs = Map.fromList <$> Gen.list (Range.linear 1 7) genXMLAttr

genXMLAttr :: Gen (Name, ST)
genXMLAttr = (,) <$> genXMLName <*> genNiceWord

genXMLInstruction :: Gen Instruction
genXMLInstruction = Instruction <$> genNiceWord <*> genNiceWord

genUUID :: Gen UUID.UUID
genUUID = Gen.element someUUIDs
  where
    someUUIDs :: [UUID.UUID]
    someUUIDs = catMaybes $ UUID.fromText <$>
      [ "b83919ba-792c-11e8-87a6-5be4268de632"
      , "b8fd2ad0-792c-11e8-9e90-8fed1fff12b4"
      , "b924b6cc-792c-11e8-992c-4754ae6de3a2"
      , "b9479610-792c-11e8-adf7-03c8d9d56542"
      , "d20556a6-792c-11e8-8a98-47e39b3c575f"
      ]

genIdPId :: Gen IdPId
genIdPId = IdPId <$> genUUID

genSignedCertificate :: Gen X509.SignedCertificate
genSignedCertificate = either (error . show) pure $ DSig.parseKeyInfo
  "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk</X509Certificate></X509Data></KeyInfo>"

genIdPConfig :: Gen a -> Gen (IdPConfig a)
genIdPConfig genExtra = do
  _idpId          <- genIdPId
  _idpMetadataURI <- genURI
  _idpMetadata    <- genIdPMetadata
  _idpExtraInfo   <- genExtra
  pure IdPConfig {..}

genFormRedirect :: Gen a -> Gen (FormRedirect a)
genFormRedirect genBody = FormRedirect <$> genURI <*> genBody


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

instance Arbitrary Issuer where
  arbitrary = TQH.hedgehog genIssuer

instance Arbitrary Locality where
  arbitrary = TQH.hedgehog genLocality

instance Arbitrary NameID where
  arbitrary = TQH.hedgehog genNameID

instance Arbitrary payload => Arbitrary (Response payload) where
  arbitrary = TQH.hedgehog (genResponse $ THQ.quickcheck arbitrary)

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

instance Arbitrary IdPId where
  arbitrary = TQH.hedgehog genIdPId

instance Arbitrary X509.SignedCertificate where
  arbitrary = TQH.hedgehog genSignedCertificate

instance Arbitrary a => Arbitrary (IdPConfig a) where
  arbitrary = TQH.hedgehog (genIdPConfig (THQ.quickcheck arbitrary))

instance Arbitrary a => Arbitrary (FormRedirect a) where
  arbitrary = TQH.hedgehog (genFormRedirect (THQ.quickcheck arbitrary))

instance Arbitrary Document where
  arbitrary = TQH.hedgehog genXMLDocument
  shrink (Document pro el epi) = (\el' -> Document pro el' epi) <$> shrinkElement el

instance Arbitrary Node where
  arbitrary = TQH.hedgehog genXMLNode
  shrink = shrinkNode

instance Arbitrary Name where
  arbitrary = TQH.hedgehog genXMLName

shrinkElement :: Element -> [Element]
shrinkElement (Element tag attrs nodes) = case (shrinkAttrs attrs, shrink nodes) of
  ([], []) -> []
  (attrs', []) -> (\shrunk -> Element tag shrunk nodes) <$> attrs'
  ([], nodes') -> (\shrunk -> Element tag attrs shrunk) <$> nodes'
  (attrs', nodes') -> Element tag <$> attrs' <*> nodes'

shrinkAttrs :: Map.Map Name ST.Text -> [Map.Map Name ST.Text]
shrinkAttrs = fmap Map.fromList . shallowShrinkList . Map.toList

shrinkNode :: Node -> [Node]
shrinkNode (NodeElement el) = NodeElement <$> shrinkElement el
shrinkNode (NodeInstruction _) = []
shrinkNode (NodeContent "") = []
shrinkNode (NodeContent _) = [NodeContent ""]
shrinkNode (NodeComment "") = []
shrinkNode (NodeComment _) = [NodeComment ""]

shallowShrinkList :: Eq a => [a] -> [[a]]
shallowShrinkList [] = []
shallowShrinkList [_] = []
shallowShrinkList xs@(_:_:_) = [] : ((:[]) <$> xs)
