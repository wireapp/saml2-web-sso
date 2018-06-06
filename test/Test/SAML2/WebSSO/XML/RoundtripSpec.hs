{-# OPTIONS_GHC -Wno-unused-binds #-}

module Test.SAML2.WebSSO.XML.RoundtripSpec (spec) where

import SAML2.WebSSO.Test.Arbitrary
import Hedgehog
import SAML2.WebSSO
import Test.Hspec
import Util


spec :: Spec
spec = hedgehog $ checkParallel $$(discover)

mkprop :: forall a. (Eq a, Show a, HasXML a) => Gen a -> Property
mkprop gen = property $ forAll gen >>= \v -> tripping v enc dec
  where
    (enc, dec) =
      (encodeElem, decodeElem @a @(Either String))
      -- (render, (parse @a @(Either String)))


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
