{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns -Wno-unused-imports #-}

module Test.SAML2.WebSSO.XMLSpec (spec) where

import Control.Exception
import Control.Lens
import Control.Monad (forM_)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader
import Data.Either
import Data.List.NonEmpty as NL
import Data.String.Conversions
import SAML2.Util
import SAML2.WebSSO
import SAML2.WebSSO.Types
import SAML2.WebSSO.Test.Credentials
import SAML2.WebSSO.Test.Lenses
import SAML2.WebSSO.Test.MockResponse
import System.Environment (setEnv)
import System.IO.Unsafe (unsafePerformIO)
import Test.Hspec
import Text.Show.Pretty (ppShow)
import Text.XML
import Text.XML.DSig as DSig
import URI.ByteString
import Util

import qualified Data.ByteString.Base64.Lazy as EL (decodeLenient)
import qualified Data.List as List
import qualified Data.Map as Map
import qualified Samples

-- | embed an email into a valid NameID context
xmlWithName :: LT -> LT -> LT
xmlWithName format email =  "<NameID xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:samla=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlm=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"" <> format <> "\">" <> email <> "</NameID>"

emailFormat :: LT
emailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

unspecifiedFormat :: LT
unspecifiedFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

entityFormat :: LT
entityFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"


spec :: Spec
spec = describe "XML Sanitization" $ do
  describe "decodeElem" $ do
    it "should decode a valid email" $ do
      decodeElem (xmlWithName emailFormat "somebody@example.org")
        `shouldBe` (emailNameID "somebody@example.org" :: Either String NameID)

    it "should fail to decode an invalid email" $ do
      decodeElem @NameID (xmlWithName emailFormat "&lt;somebody@example.org&gt;")
        `shouldSatisfy` isLeft

    it "should decode an escaped name if format is unspecified" $ do
      decodeElem (xmlWithName unspecifiedFormat "&lt;somebody@example.org&gt;")
        `shouldBe` Right (unspecifiedNameID "<somebody@example.org>" :: NameID)

    it "should unescape names" $ do
      decodeElem (xmlWithName unspecifiedFormat "&lt;somebody@example.org&gt;")
        `shouldBe` Right (unspecifiedNameID "<somebody@example.org>" :: NameID)

    it "should not unescape more than once" $ do
      decodeElem
        (xmlWithName unspecifiedFormat "&amp;lt;somebody@example.org&amp;gt;")
        `shouldBe` (mkNameID
                      (UNameIDUnspecified
                         (mkXmlText "&lt;somebody@example.org&gt;"))
                      Nothing
                      Nothing
                      Nothing :: Either String NameID)

    it "should not unescape text multiple times" $ do
      decodeElem (xmlWithName entityFormat "https://www.google.com/search?q=hello&lt;world&gt;")
        `shouldBe` (mkNameID
                      (UNameIDEntity
                         (fromRight (error "bad uri in tests")
                          $ parseURI' "https://www.google.com/search?q=hello<world>"))
                      Nothing
                      Nothing
                      Nothing :: Either String NameID)

    it "rendering doesn't double escape" $ do
       False `shouldBe` True
