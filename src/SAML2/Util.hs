{-# LANGUAGE OverloadedStrings #-}

module SAML2.Util (module SAML2.Util, module Text.XML.Util)
where

import Control.Monad.Except
import Data.String.Conversions
import Data.Typeable
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

-- | fmap an outer computation into an inner computation that may fail, then flip inner @n@ and
-- outer @m@.  (except for the flip, this is just 'fmap'.)
fmapFlipM :: (Monad m, Traversable n) => (a -> m b) -> n a -> m (n b)
fmapFlipM f = sequence . fmap f
