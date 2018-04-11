{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ViewPatterns        #-}

{-# OPTIONS_GHC -Wno-unused-binds #-}

module Test.Util where

import Control.Monad (unless)
import Data.EitherR
import Data.List
import Data.Generics.Uniplate.Data
import Data.String.Conversions
import System.IO.Temp
import System.Process (system)
import Test.Tasty
import Test.Tasty.HUnit
import Text.Show.Pretty
import Text.XML
import URI.ByteString

import SAML.WebSSO


render' :: Document -> LT
render' = renderText $ def
  { rsPretty         = True
--  , rsNamespaces :: [(Text, Text)]
--  , rsAttrOrder :: Name -> Map.Map Name Text -> [(Name, Text)]
--  , rsUseCDATA :: Content -> Bool
--  , rsXMLDeclaration :: Bool
  }

rerender' :: LT -> LT
rerender' = render' . parseText_ def

rerenderFile :: FilePath -> IO ()
rerenderFile fp = Prelude.writeFile (fp <> "-") =<< (cs . rerender' . cs . dropWhile (/= '<') <$> Prelude.readFile fp)

mkURI :: String -> URI
mkURI = (\(Just x) -> x) . parseURI' . cs

hedgehog :: IO Bool -> TestTree
hedgehog ht = testCase "hedgehog tests" $ assertBool "failed" =<< ht


roundtrip :: forall a. (Eq a, Show a, HasXMLRoot a) => Int -> LT -> a -> TestTree
roundtrip serial rendered parsed = testGroup ("roundtrip-" <> show serial)
  [ testCase "encode" $ assertXmlRoundtrip "failed"
      (fmapL show . parseText def $ rendered)
      (fmapL show . parseText def $ encode parsed)
  , testCase "decode" $ assertEqual "failed"
      (Right parsed)
      (fmapL show $ decode rendered)
  ]

-- | If we get two XML structures that differ, compute the diff.
assertXmlRoundtrip :: HasCallStack
  => String -> Either String Document -> Either String Document -> Test.Tasty.HUnit.Assertion
assertXmlRoundtrip msg (Right (normalizeDocument -> x)) (Right (normalizeDocument -> y))
  = assertXmlRoundtripFailWithDiff msg x y
assertXmlRoundtrip msg x y
  = assertEqual msg x y


assertXmlRoundtripFailWithDiff :: HasCallStack
  => String -> Document -> Document -> Test.Tasty.HUnit.Assertion
assertXmlRoundtripFailWithDiff msg x y = unless (x == y) .
  withSystemTempDirectory "saml.web.sso.tmp" $ \tmpdir -> do
    let tmpx = tmpdir <> "/x"
        tmpy = tmpdir <> "/y"
        tmpd = tmpdir <> "/xy"
    x `seq` Prelude.writeFile tmpx (ppShow x)
    y `seq` Prelude.writeFile tmpy (ppShow y)
    _ <- system $ "diff " <> tmpx <> " " <> tmpy <> " > " <> tmpd
    diff <- Prelude.readFile tmpd
    assertBool (msg <> ": non-empty diff:\n" <> diff <> "\n\nyour output:\n" <> ppShow y) False


-- | Make two 'Document' values that are supposed to be equal easier to compare:
--
-- * render and parse back to normalize the locations where namespaces are declared
-- * sort all children and remove digital signatures
-- * remove all namespace prefices
normalizeDocument :: HasCallStack => Document -> Document
normalizeDocument = renderAndParse . transformBis
  [ [transformer $ \(Name nm nmspace _prefix) -> Name nm nmspace Nothing]
  , [transformer $ \(Element nm attrs nodes) -> Element nm attrs (sort . filter (not . isSignature) $ nodes)]
  ]

renderAndParse :: HasCallStack => Document -> Document
renderAndParse doc = case parseText def $ renderText def { rsPretty = True } doc of
  Right doc'   -> doc'
  bad@(Left _) -> error $ "impossible: " <> show bad

isSignature :: Node -> Bool
isSignature (NodeElement (Element name _ _)) = name == "{http://www.w3.org/2000/09/xmldsig#}Signature"
isSignature _ = False
