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
      have <- ioFromTestSP testCtx1 $ spDesc
        "drnick" [uri|http://example.com/|] [uri|http://example.com/sso/login|] (fallbackContact :| [])
      let want = spDescPre (have ^. spdID)
      have `shouldBe` want

  describe "spMeta" $ do
    it "does not smoke" $ do
      let given = spDescPre . fromJust $ UUID.fromText "e3a565aa-1392-4446-a4d6-3771453808f0"
          SPDesc (want :: Document) = spMeta given
      have :: Either String Document <- fmapL show . parseText def . cs <$> readSampleIO "our-spssodescriptor.xml"
      have `shouldBe` Right want


spDescPre :: UUID.UUID -> SPDescPre
spDescPre uuid = SPDescPre
  { _spdID = uuid
  , _spdValidUntil = fromTime $ addTime (60 * 60 * 24 * 365) timeNow
  , _spdCacheDuration = 2592000
  , _spdOrgName = "drnick"
  , _spdOrgDisplayName = "drnick"
  , _spdOrgURL = [uri|http://example.com/|]
  , _spdResponseURL = [uri|http://example.com/sso/login|]
  , _spdContacts = fallbackContact :| []
  }
