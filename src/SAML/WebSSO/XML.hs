{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE DefaultSignatures   #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE ViewPatterns        #-}

module SAML.WebSSO.XML where

import Control.Category (Category(..))
import Control.Exception (ErrorCall(..))
import Control.Monad.Catch
import Data.Monoid ((<>))
import Data.String.Conversions
import qualified Data.Text as ST
import Data.Typeable (Proxy(Proxy), Typeable, typeOf)
import Prelude hiding ((.))
import Text.XML hiding (renderText)
import qualified Text.XML
import Text.XML.Cursor
import URI.ByteString

import SAML.WebSSO.Types


----------------------------------------------------------------------
-- HasXML class

encode :: forall a. HasXMLRoot a => a -> LT
encode = Text.XML.renderText settings . renderToDocument
  where
    settings = def { rsNamespaces = nameSpaces (Proxy @a), rsXMLDeclaration = False }

decode :: forall m a. (HasXMLRoot a, MonadThrow m) => LT -> m a
decode = either throwM parseFromDocument . parseText def


renderToDocument :: HasXMLRoot a => a -> Document
renderToDocument (renderRoot -> el) = Document defPrologue el defMiscellaneous

defPrologue :: Prologue
defPrologue = Prologue [] Nothing []

defMiscellaneous :: [Miscellaneous]
defMiscellaneous = []


parseFromDocument :: (HasXML a, MonadThrow m) => Document -> m a
parseFromDocument = parse . fromDocument


die :: forall a b c m. (Typeable a, Show b, MonadThrow m) => Proxy a -> b -> m c
die Proxy msg = throwM . ErrorCall $
  "HasXML: could not parse " <> show (typeOf @a undefined) <> ": " <> show msg


defNameSpaces :: [(ST, ST)]
defNameSpaces =
  [ ("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
  , ("samla", "urn:oasis:names:tc:SAML:2.0:assertion")
  , ("samlm", "urn:oasis:names:tc:SAML:2.0:metadata")
  , ("ds", "http://www.w3.org/2000/09/xmldsig#")
  ]


class HasXML a where
  nameSpaces :: Proxy a -> [(ST, ST)]
  nameSpaces Proxy = defNameSpaces

  render :: a -> [Node]
  default render :: HasXMLRoot a => a -> [Node]
  render = (:[]) . NodeElement . renderRoot

  parse  :: MonadThrow m => Cursor -> m a

class HasXML a => HasXMLRoot a where
  renderRoot :: a -> Element


instance HasXML Document where
  parse (node -> NodeElement el) = pure $ Document defPrologue el defMiscellaneous
  parse bad = die (Proxy @Document) bad

instance HasXMLRoot Document where
  renderRoot (Document _ el _) = el


----------------------------------------------------------------------
-- util

renderURI :: URI -> ST
renderURI = cs . serializeURIRef'

parseURI' :: MonadThrow m => ST -> m URI  -- TODO: find a better name.  make renderURI match that name.
parseURI' = either (die (Proxy @URI)) pure . parseURI laxURIParserOptions . cs . ST.strip


----------------------------------------------------------------------
-- hack: use hsaml2 parsers and convert from SAMLProtocol instances

instance HasXML EntityDescriptor where
  parse = undefined

instance HasXMLRoot EntityDescriptor where
  renderRoot = undefined

instance HasXML AuthnRequest where
  parse = undefined

instance HasXMLRoot AuthnRequest where
  renderRoot = undefined

instance HasXML AuthnResponse where
  parse = undefined

instance HasXMLRoot AuthnResponse where
  renderRoot = undefined
