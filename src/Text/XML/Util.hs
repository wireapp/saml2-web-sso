{-# LANGUAGE OverloadedStrings #-}

module Text.XML.Util
where

import Control.Monad.Except
import Data.Char (isSpace)
import Data.Default (Default(..))
import Data.Map as Map
import Data.String.Conversions
import Data.Typeable
import GHC.Stack
import Text.XML
import URI.ByteString

import qualified Data.ByteString.Lazy as BSL
import qualified Data.Generics.Uniplate.Data as Uniplate
import qualified Data.Text as ST
import qualified SAML2.XML as HS
import qualified Text.XML.HXT.Core as HXT
import qualified Data.Tree.NTree.TypeDefs as HXT
import qualified Text.XML.HXT.DOM.ShowXml


die :: forall (a :: *) b c m. (Typeable a, Show b, MonadError String m) => Proxy a -> b -> m c
die Proxy msg = throwError $
  "HasXML: could not parse " <> show (typeOf @a undefined) <> ": " <> show msg


renderURI :: URI -> ST
renderURI = cs . serializeURIRef'

parseURI' :: MonadError String m => ST -> m URI
parseURI' = either (die (Proxy @URI)) pure . parseURI laxURIParserOptions . cs . ST.strip

-- | You probably should not use this.  If you have a string literal, consider "URI.ByteString.QQ".
unsafeParseURI :: ST -> URI
unsafeParseURI = either (error . ("could not parse config: " <>) . show) id . parseURI'

-- | fmap an outer computation into an inner computation that may fail, then flip inner @n@ and
-- outer @m@.  (except for the flip, this is just 'fmap'.)
fmapFlipM :: (Monad m, Traversable n) => (a -> m b) -> n a -> m (n b)
fmapFlipM f = sequence . fmap f


type Attrs = Map.Map Name ST


nodesToDoc :: HasCallStack => [Node] -> Document
nodesToDoc [NodeElement el] = mkDocument el
nodesToDoc bad = error $ show bad

mkDocument :: Element -> Document
mkDocument el = Document defPrologue el defMiscellaneous

defPrologue :: Prologue
defPrologue = Prologue [] Nothing []

defMiscellaneous :: [Miscellaneous]
defMiscellaneous = []


hxtToConduit :: MonadError String m => HXT.XmlTree -> m Document
hxtToConduit = either (throwError . ("hxtToConduit: parseLBS failed: " <>) . show) pure . parseLBS def . docToXML'

conduitToHxt :: MonadError String m => Document -> m HXT.XmlTree
conduitToHxt = either (throwError . ("conduitToHxt: xmlToDoc' failed: " <>)) pure . xmlToDoc' . renderLBS def { rsXMLDeclaration = False }

samlToConduit :: (MonadError String m, HXT.XmlPickler a) => a -> m Document
samlToConduit = either  (throwError . ("samlToConduit: parseLBS failed: " <>) . show) pure . parseLBS def . HS.samlToXML


-- | This is subtly different from HS.docToXML' and should probably be moved to hsaml2.
docToXML' :: HXT.XmlTree -> BSL.ByteString
docToXML' = Text.XML.HXT.DOM.ShowXml.xshowBlob . (:[])

-- | This is subtly different from HS.xmlToDoc' and should probably be moved to hsaml2.
xmlToDoc' :: MonadError String m => BSL.ByteString -> m HXT.XmlTree
xmlToDoc' xml = case HXT.runLA HXT.xread (cs xml) of
  [HXT.NTree (HXT.XError _errcode errmsg) _] -> throwError errmsg
  [t] -> pure t
  [] -> throwError "no root elements"
  bad@(_:_:_) -> throwError $ "more than one root element: " <> show (length bad)


-- | Remove all whitespace in the text nodes of the xml document.
stripWhitespace :: Document -> Document
stripWhitespace = Uniplate.transformBis
  [ [Uniplate.transformer $ \case
        (NodeContent txt) -> NodeContent $ ST.filter (not . isSpace) txt
        other -> other
    ]
  , [Uniplate.transformer $ \case
        (Element nm attrs nodes) -> Element nm attrs (Prelude.filter (/= NodeContent "") $ nodes)
    ]
  ]

-- | if two content nodes are next to each other, concatenate them into one.  NB: if you call
-- 'stripWhitespace' it should be called *after* 'mergeContentSiblings', or some two words will be
-- merged into one.
mergeContentSiblings :: Document -> Document
mergeContentSiblings = Uniplate.transformBis
  [ [Uniplate.transformer $ \case
        (Element nm attrs nodes) -> Element nm attrs (go nodes)
    ]
  ]
  where
    go [] = []
    go (NodeContent s : NodeContent t : xs) = go $ NodeContent (s <> t) : xs
    go (x : xs) = x : go xs

normalizeDoc :: Document -> Document
normalizeDoc = stripWhitespace . mergeContentSiblings
