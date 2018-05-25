{-# OPTIONS_GHC -Wno-unused-binds #-}

module Util where

import Control.Exception (throwIO, ErrorCall(ErrorCall))
import Control.Monad
import Data.EitherR
import Data.Generics.Uniplate.Data
import Data.List
import Data.String.Conversions
import Data.Typeable
import GHC.Stack
import SAML2.WebSSO
import System.Environment
import System.FilePath
import System.IO.Temp
import System.IO.Unsafe (unsafePerformIO)
import System.Process (system)
import Test.Hspec
import Text.Show.Pretty
import Text.XML
import Text.XML.Util
import URI.ByteString

import qualified Data.Text.Lazy.IO as LT


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

mkURI :: HasCallStack => String -> URI
mkURI = unsafeParseURI . cs

hedgehog :: IO Bool -> Spec
hedgehog = it "hedgehog tests" . (`shouldReturn` True)


-- | Helper function for generating new tests cases.
haskellCodeFromXML :: forall a. (Typeable a, Show a, HasXMLRoot a) => Proxy a -> FilePath -> IO ()
haskellCodeFromXML Proxy ifilepath_ = do
  root <- getEnv "SAML2_WEB_SSO_ROOT"
  let ifilepath = root </> "test/xml" </> ifilepath_
      ofilepath = root </> "test/Samples.hs"

      f :: String -> IO a
      f = either (throwIO . ErrorCall) pure . decode . cs

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


{-# NOINLINE readSample #-}
readSample :: FilePath -> LT
readSample = unsafePerformIO . readSampleIO

readSampleIO :: FilePath -> IO LT
readSampleIO fpath = do
  root <- getEnv "SAML2_WEB_SSO_ROOT"
  LT.readFile $ root </> "test/samples" </> fpath


roundtrip :: forall a. (Eq a, Show a, HasXMLRoot a) => Int -> LT -> a -> Spec
roundtrip serial rendered parsed = describe ("roundtrip-" <> show serial) $ do
  let tweak = fmapL show . parseText def
  it "encode" $ tweak rendered `assertXmlRoundtrip` tweak (encode parsed)
  it "decode" $ Right parsed `shouldBe` fmapL show (decode rendered)

-- | If we get two XML structures that differ, compute the diff.
assertXmlRoundtrip :: HasCallStack
  => Either String Document -> Either String Document -> Expectation
assertXmlRoundtrip (Right (normalizeDocument -> x)) (Right (normalizeDocument -> y))
  = assertXmlRoundtripFailWithDiff x y
assertXmlRoundtrip x y
  = x `shouldBe` y


assertXmlRoundtripFailWithDiff :: HasCallStack
  => Document -> Document -> Expectation
assertXmlRoundtripFailWithDiff x y = unless (x == y) .
  withSystemTempDirectory "saml.web.sso.tmp" $ \tmpdir -> do
    let tmpx = tmpdir <> "/x"
        tmpy = tmpdir <> "/y"
        tmpd = tmpdir <> "/xy"
    x `seq` Prelude.writeFile tmpx (ppShow x)
    y `seq` Prelude.writeFile tmpy (ppShow y)
    _ <- system $ "diff " <> tmpx <> " " <> tmpy <> " > " <> tmpd
    diff <- Prelude.readFile tmpd
    expectationFailure ("non-empty diff:\n" <> diff <> "\n\nyour output:\n" <> ppShow y)


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
