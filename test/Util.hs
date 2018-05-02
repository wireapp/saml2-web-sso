{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}

{-# OPTIONS_GHC -Wno-unused-binds #-}

module Util where

import Control.Monad
import Data.EitherR
import Data.List
import Data.Generics.Uniplate.Data
import Data.String.Conversions
import Data.Typeable
import System.Environment
import System.FilePath
import System.IO.Temp
import System.IO.Unsafe (unsafePerformIO)
import System.Process (system)
import Test.Tasty
import Test.Tasty.HUnit
import Text.Show.Pretty
import Text.XML
import URI.ByteString
import Hedgehog

import qualified Data.Text as ST
import qualified Data.Text.Lazy.IO as LT
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

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

showFile :: FilePath -> IO String
showFile fp = cs . rerender' . cs . dropWhile (/= '<') <$> Prelude.readFile fp

dumpFile :: FilePath -> IO ()
dumpFile = showFile >=> putStrLn

rerenderFile :: FilePath -> IO ()
rerenderFile fp = showFile fp >>= Prelude.writeFile (fp <> "-")

mkURI :: String -> URI
mkURI = (\(Just x) -> x) . parseURI' . cs

-- TODO: this overwrites output of the other tests.  there must be a way in tasty to collect
-- stdout/stderr and add it to the output in a more orderly fashion.
hedgehog :: IO Bool -> TestTree
hedgehog ht = testCase "hedgehog tests" $ assertBool "failed" =<< ht


-- | Helper function for generating new tests cases.
haskellCodeFromXML :: forall a. (Typeable a, Show a, HasXMLRoot a) => Proxy a -> FilePath -> IO ()
haskellCodeFromXML Proxy ifilepath_ = do
  root <- getEnv "SAML2_WEB_SSO_ROOT"
  let ifilepath = root </> "test/xml" </> ifilepath_
      ofilepath = root </> "test/Samples.hs"

      f :: String -> IO a
      f = decode . cs

      g :: a -> String
      g = (<> mconcat aft) . (mconcat bef <>) . show
        where
          bef = [ "\n\n", fnm, " :: ", show (typeOf (undefined :: a)), "\n", fnm, " = "]
          aft = ["\n\n"]

          fnm = takeWhile (/= '.') $ fmap (\case '-' -> '_'; c -> c) ifilepath_

  typ <- f =<< Prelude.readFile ifilepath
  print (ifilepath, ofilepath)
  putStrLn . cs . encode $ typ
  Prelude.appendFile ofilepath $ g typ


{-# NOINLINE readXmlSample #-}
readXmlSample :: FilePath -> LT
readXmlSample fpath = unsafePerformIO $ do
  root <- getEnv "SAML2_WEB_SSO_ROOT"
  LT.readFile $ root </> "test/xml" </> fpath


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


-- | pick N words from a dictionary of popular estonian first names.  this should yield enough
-- entropy, but is much nicer to read.
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
