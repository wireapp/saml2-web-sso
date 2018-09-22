{-# LANGUAGE OverloadedStrings #-}

module SAML2.Util (module SAML2.Util, module Text.XML.Util)
where

import Control.Monad.Except
import Data.String.Conversions
import Data.Typeable
import GHC.Stack
import Lens.Micro
import Text.XML.Util
import URI.ByteString

import qualified Data.Text as ST


die :: forall (a :: *) b c m. (Typeable a, Show b, MonadError String m) => Proxy a -> b -> m c
die = die' Nothing

die' :: forall (a :: *) b c m. (Typeable a, Show b, MonadError String m) => Maybe String -> Proxy a -> b -> m c
die' mextra Proxy msg = throwError $
  "HasXML: could not parse " <> show (typeOf @a undefined) <> ": " <> show msg <> maybe "" ("; " <>) mextra


renderURI :: URI -> ST
renderURI = cs . serializeURIRef'

parseURI' :: MonadError String m => ST -> m URI
parseURI' uri = either (die' (Just $ show uri) (Proxy @URI)) pure . parseURI laxURIParserOptions . cs . ST.strip $ uri

-- | You probably should not use this.  If you have a string literal, consider "URI.ByteString.QQ".
unsafeParseURI :: ST -> URI
unsafeParseURI = either (error . ("could not parse config: " <>) . show) id . parseURI'

-- | @uriSegments "/one/two" == uriSegments "one/two/" == uriSegments "///one//two///" == ["one", "two"]@
uriSegments :: ST -> [ST]
uriSegments = filter (not . ST.null) . ST.splitOn "/"

uriUnSegments :: [ST] -> ST
uriUnSegments = ("/" <>) . ST.intercalate "/"

(-/) :: HasCallStack => ST -> ST -> ST
oldpath -/ pathext = uriUnSegments . uriSegments $ oldpath <> "/" <> pathext

(=/) :: HasCallStack => URI -> ST -> URI
uri =/ pathext = normURI $ uri & pathL %~ (<> "/" <> cs pathext)

normURI :: URI -> URI
normURI = unsafeParseURI . cs . normalizeURIRef' URINormalizationOptions
  { unoDowncaseScheme    = True
  , unoDowncaseHost      = True
  , unoDropDefPort       = False
  , unoSlashEmptyPath    = True
  , unoDropExtraSlashes  = True
  , unoSortParameters    = True
  , unoRemoveDotSegments = True
  , unoDefaultPorts      = mempty
  }

-- | fmap an outer computation into an inner computation that may fail, then flip inner @n@ and
-- outer @m@.  (except for the flip, this is just 'fmap'.)
fmapFlipM :: (Monad m, Traversable n) => (a -> m b) -> n a -> m (n b)
fmapFlipM f = sequence . fmap f
