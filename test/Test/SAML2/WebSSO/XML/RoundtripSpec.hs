{-# OPTIONS_GHC -Wno-unused-binds #-}

module Test.SAML2.WebSSO.XML.RoundtripSpec (spec) where

import Control.Lens
import Data.List
import Data.Proxy
import Hedgehog
import Hedgehog.Gen as Gen
import SAML2.WebSSO
import SAML2.WebSSO.Test.Arbitrary
import Test.Hspec
import Util

import qualified Data.List.NonEmpty as NL
import qualified SAML2.Core as HS


spec :: Spec
spec = hedgehog $ checkParallel $$(discover)

numTests :: TestLimit
numTests = 120

mkpropHasXML
  :: forall a. (Eq a, Show a, HasXML a)
  => Gen a -> Property
mkpropHasXML = mkpropHasXML' id

mkpropHasXML'
  :: forall a. (Eq a, Show a, HasXML a)
  => (a -> a) -> Gen a -> Property
mkpropHasXML' canon gen = withTests numTests . property $ do
  v <- forAll (canon <$> gen)
  tripping v encodeElem (fmap canon . decodeElem @a @(Either String))

mkpropHasXMLImport
  :: forall them us. (Eq us, Show us, Show them, HasXMLImport us them)
  => Proxy them -> Gen us -> Property
mkpropHasXMLImport = mkpropHasXMLImport' id

mkpropHasXMLImport'
  :: forall them us. (Eq us, Show us, Show them, HasXMLImport us them)
  => (us -> us) -> Proxy them -> Gen us -> Property
mkpropHasXMLImport' canon _ gen = withTests numTests . property $ do
  v <- forAll (canon <$> gen)
  tripping v exportXml (fmap canon . importXml @us @them @(Either String))


prop_tripNameID :: Property
prop_tripNameID = mkpropHasXML genNameID

prop_tripIdPMetadata :: Property
prop_tripIdPMetadata = mkpropHasXML genIdPMetadata

prop_tripSPMetadata :: Property
prop_tripSPMetadata = mkpropHasXML genSPMetadata

prop_tripAuthnRequest :: Property
prop_tripAuthnRequest = mkpropHasXML genAuthnRequest

prop_tripConditions :: Property
prop_tripConditions = mkpropHasXML' canonicalizeConditions . Gen.prune $ genConditions

prop_tripConditions' :: Property
prop_tripConditions' = mkpropHasXMLImport' canonicalizeConditions (Proxy @HS.Conditions) . Gen.prune $ genConditions

canonicalizeConditions :: Conditions -> Conditions
canonicalizeConditions = condAudienceRestriction %~ sort . fmap NL.sort

prop_tripAuthnResponse :: Property
prop_tripAuthnResponse = mkpropHasXML' canonicalizeAuthnResponse . Gen.prune $ genAuthnResponse
  -- without the 'prune', this triggers https://github.com/hedgehogqa/haskell-hedgehog/issues/174

canonicalizeAuthnResponse :: AuthnResponse -> AuthnResponse
canonicalizeAuthnResponse = rspPayload %~ fmap (assConditions . _Just %~ canonicalizeConditions)
