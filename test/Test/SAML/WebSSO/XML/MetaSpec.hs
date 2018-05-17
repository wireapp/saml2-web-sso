{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE InstanceSigs         #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE RankNTypes           #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE ViewPatterns         #-}

module Test.SAML.WebSSO.XML.MetaSpec (spec) where

import Data.EitherR
import Data.String.Conversions
import Data.Time
import SAML.WebSSO
import Test.Hspec
import TestSP
import Text.XML
import Text.XML.Util
import Util

spec :: Spec
spec = do
  describe "spDesc" $ do
    it "does not smoke" $ do
      have <- testSP testCtx1 $ spDesc "drnick" (unsafeParseURI "http://example.com/") (unsafeParseURI "http://example.com/sso/login")
      let want = SPDescPre
            { _spdValidUntil = addUTCTime (60 * 60 * 24 * 365) $ fromTime timeNow
            , _spdCacheDuration = 2592000
            , _spdOrgName = "drnick"
            , _spdOrgDisplayName = "drnick"
            , _spdOrgURL = unsafeParseURI "http://example.com/"
            , _spdResponseURL = unsafeParseURI "http://example.com/sso/login"
            }
      have `shouldBe` want

  describe "spMeta" $ do
    it "does not smoke" $ do
      let given = SPDescPre
            { _spdValidUntil = addUTCTime (60 * 60 * 24 * 365) $ fromTime timeNow
            , _spdCacheDuration = 2592000
            , _spdOrgName = "drnick"
            , _spdOrgDisplayName = "drnick"
            , _spdOrgURL = unsafeParseURI "http://example.com/"
            , _spdResponseURL = unsafeParseURI "http://example.com/sso/login"
            }
          SPDesc (want :: Document) = spMeta given
          have :: Either String Document = fmapL show . parseText def . cs $ readSample "our-spssodescriptor.xml"
      have `shouldBe` Right want
