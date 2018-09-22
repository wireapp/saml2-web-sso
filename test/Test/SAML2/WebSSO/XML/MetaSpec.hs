{-# LANGUAGE OverloadedStrings #-}

module Test.SAML2.WebSSO.XML.MetaSpec (spec) where

import Control.Lens
import Data.EitherR
import Data.List.NonEmpty (NonEmpty((:|)))
import Data.Maybe (fromJust)
import Data.String.Conversions
import SAML2.WebSSO
import Test.Hspec
import TestSP
import Text.XML
import URI.ByteString.QQ
import Util

import qualified Data.UUID as UUID


spec :: Spec
spec = do
  describe "spDesc" $ do
    it "does not smoke" $ do
      testCtx1 <- mkTestCtx1
      have <- ioFromTestSP testCtx1 $ mkSPMetadata
        "drnick" [uri|http://example.com/|] [uri|http://example.com/sso/login|] (fallbackContact :| [])
      let want = testSPMetadata (have ^. spID)
      have `shouldBe` want

  describe "spMeta" $ do
    it "does not smoke" $ do
      let given = testSPMetadata . fromJust . UUID.fromText $ "e3a565aa-1392-4446-a4d6-3771453808f0"
          want = renderToDocument given
      have :: Either String Document <- fmapL show . parseText def . cs <$> readSampleIO "our-spssodescriptor.xml"
      have `shouldBe` Right want


testSPMetadata :: UUID.UUID -> SPMetadata
testSPMetadata uuid = SPMetadata
  { _spID = uuid
  , _spValidUntil = fromTime $ addTime (60 * 60 * 24 * 365) timeNow
  , _spCacheDuration = 2592000
  , _spOrgName = "drnick"
  , _spOrgDisplayName = "drnick"
  , _spOrgURL = [uri|http://example.com/|]
  , _spResponseURL = [uri|http://example.com/sso/login|]
  , _spContacts = fallbackContact :| []
  }
