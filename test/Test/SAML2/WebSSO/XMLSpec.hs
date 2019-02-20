{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-unused-binds -Wno-incomplete-patterns -Wno-incomplete-uni-patterns #-}

module Test.SAML2.WebSSO.XMLSpec (spec) where

import Data.Either
import Data.String.Conversions
import SAML2.Util
import SAML2.WebSSO
import Test.Hspec

import qualified Data.Text.Lazy as LT
import qualified SAML2.Core as HS
import qualified SAML2.XML as HS

-- | embed an email into a valid NameID context
xmlWithName :: Maybe LT -> LT -> LT
xmlWithName mformat email = "<NameID " <> namespaces <> format <> ">" <> email <> "</NameID>"
  where
    namespaces = LT.unwords
      [ "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
      , "xmlns:samla=\"urn:oasis:names:tc:SAML:2.0:assertion\""
      , "xmlns:samlm=\"urn:oasis:names:tc:SAML:2.0:metadata\""
      , "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
      , "xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\""
      ]
    format = maybe "" (\f -> " Format=\"" <> f <> "\"") mformat

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
      decodeElem (xmlWithName (Just emailFormat) "somebody@example.org")
        `shouldBe` (emailNameID "somebody@example.org" :: Either String NameID)

    it "should fail to decode an invalid email" $ do
      decodeElem @NameID (xmlWithName (Just emailFormat) "&lt;somebody@example.org&gt;")
        `shouldSatisfy` isLeft

    it "should decode an escaped name if format is unspecified" $ do
      decodeElem (xmlWithName (Just unspecifiedFormat) "&lt;somebody@example.org&gt;")
        `shouldBe` Right (unspecifiedNameID "<somebody@example.org>")

    it "should unescape names" $ do
      decodeElem (xmlWithName (Just unspecifiedFormat) "&lt;somebody@example.org&gt;")
        `shouldBe` Right (unspecifiedNameID "<somebody@example.org>")

    it "should not unescape more than once" $ do
      decodeElem
        (xmlWithName (Just unspecifiedFormat) "&amp;lt;somebody@example.org&amp;gt;")
        `shouldBe` (mkNameID
                      (UNameIDUnspecified
                         (mkXmlText "&lt;somebody@example.org&gt;"))
                      Nothing
                      Nothing
                      Nothing :: Either String NameID)

    it "should not unescape text multiple times" $ do
      decodeElem (xmlWithName (Just entityFormat) "https://www.google.com/search?q=hello&lt;world&gt;")
        `shouldBe` (mkNameID
                      (UNameIDEntity
                         (fromRight (error "bad uri in tests")
                          $ parseURI' "https://www.google.com/search?q=hello<world>"))
                      Nothing
                      Nothing
                      Nothing :: Either String NameID)

    it "rendering doesn't double escape" $ do
      encodeElem (unspecifiedNameID "<something>")
        `shouldBe` (xmlWithName Nothing "&lt;something&gt;")

    it "sadly, hsaml2 does not escape unsafe strings" $ do
      -- this test case reproduces an issue with hsaml2 that motivates us manually escaping
      -- the 'XmlText's in the serialization functions here in saml2-web-sso.

      HS.samlToXML (HS.simpleNameID HS.NameIDFormatUnspecified "<something>")
        `shouldBe` "<NameID xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"><something></NameID>"
        -- it really shouldn't, though!
