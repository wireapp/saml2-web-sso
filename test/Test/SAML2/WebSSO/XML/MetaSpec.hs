{-# LANGUAGE OverloadedStrings #-}

module Test.SAML2.WebSSO.XML.MetaSpec (spec) where

import Control.Lens
import Data.EitherR
import Data.Maybe (fromJust)
import Data.String.Conversions
import Data.Time
import SAML2.WebSSO
import Test.Hspec
import TestSP
import Text.XML
import Text.XML.Util
import Util

import qualified Data.UUID as UUID


spec :: Spec
spec = do
  describe "spDesc" $ do
    it "does not smoke" $ do
      have <- testSP testCtx1 $ spDesc "drnick" (unsafeParseURI "http://example.com/") (unsafeParseURI "http://example.com/sso/login")
      let want = spdescpre (have ^. spdID)
      have `shouldBe` want

  describe "spMeta" $ do
    it "does not smoke" $ do
      let given = spdescpre . fromJust $ UUID.fromText "e3a565aa-1392-4446-a4d6-3771453808f0"
          SPDesc (want :: Document) = spMeta given
      have :: Either String Document <- fmapL show . parseText def . cs <$> readSampleIO "our-spssodescriptor.xml"
      have `shouldBe` Right want


spdescpre :: UUID.UUID -> SPDescPre
spdescpre uuid = SPDescPre
  { _spdID = uuid
  , _spdValidUntil = addUTCTime (60 * 60 * 24 * 365) $ fromTime timeNow
  , _spdCacheDuration = 2592000
  , _spdOrgName = "drnick"
  , _spdOrgDisplayName = "drnick"
  , _spdOrgURL = unsafeParseURI "http://example.com/"
  , _spdResponseURL = unsafeParseURI "http://example.com/sso/login"
  }
