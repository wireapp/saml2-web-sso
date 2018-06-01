{-# LANGUAGE OverloadedStrings #-}

-- | work in progress.  we may drop this part of teh library for some other approach.
--
-- FUTUREWORK: this is a clone of JsonGrammar for xml, and it should probably go to a separate package.
--
-- FUTUREWORK: as for the missing error messages (lens 'Prism's have 'Nothing' in case of error): use a
-- variant of 'trace' for reporting errors that can be disabled / replaced by @\x -> unsafePerformIO
-- (log x) `seq` x@ in production.
module Text.XML.Iso where

import Control.Applicative ((<|>))
import Control.Category (Category(..))
import Control.Monad
import Data.Maybe
import Data.StackPrism
import Data.String
import Data.String.Conversions
import Debug.Trace (trace)  -- (for crude logging in 'renderFailed')
import GHC.Stack
import Prelude hiding (id, (.))
import Text.Read (readMaybe)
import Text.XML
import Text.XML.Util

import qualified Data.Map as Map


----------------------------------------------------------------------
-- main

-- something like this would be better for parseXml:
-- >>> type MonadIsoXML = MonadError StackError
-- >>> type StackError = String

-- | ...  or do we want to use 'Document' instead of 'Element'?
parseXml :: (HasCallStack, IsoXML 'CtxElem a) => Element -> Maybe a
parseXml = parseElem (unstack isoXml)

renderXml :: (HasCallStack, IsoXML 'CtxElem a) => a -> Maybe Element
renderXml = renderElem (unstack isoXml)


----------------------------------------------------------------------
-- SAML name spaces

-- | Like 'Name', but the 'IsString' instance expects prefixes in the curly braces, and 'fromPName'
-- resolves them into the actual name space identifiers.
--
-- the not so nice property of this is that bad name space prefixes in string literals are
-- run-time errors.
--
-- we should find a way to pick the default name space set in the importing module, not here!
newtype PName = PName { fromPName :: Name }
  deriving (Eq, Ord, Show)

instance IsString PName where
  fromString = tweak . fromString
    where
      tweak v@(Name _ Nothing Nothing) = PName v
      tweak (Name nm (Just prfx) Nothing) = case lookup prfx defNameSpaces of
        Just ns -> PName $ Name nm (Just ns) (Just prfx)
        Nothing -> error $ "instance IsString PName: unknown prefix: " <> show prfx
      tweak bad@(Name _ _ (Just _)) = error $ "instance IsString PName: internal error: " <> show bad

defNameSpaces :: [(ST, ST)]
defNameSpaces =
  [ ("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
  , ("samla", "urn:oasis:names:tc:SAML:2.0:assertion")
  , ("samlm", "urn:oasis:names:tc:SAML:2.0:metadata")
  , ("ds", "http://www.w3.org/2000/09/xmldsig#")
  ]


----------------------------------------------------------------------
-- util

manyM :: (HasCallStack, Monad m, MonadPlus m) => (a -> m a) -> a -> m a
manyM m x = (m >=> manyM m) x `mplus` pure x

unstack :: forall c a b. HasCallStack => Grammar c (a :- ()) (b :- ()) -> Grammar c a b
unstack g = matchPure hd unhd . g . matchPure unhd hd
  where
    hd (x :- ()) = pure x
    unhd x       = pure (x :- ())

fromPrism :: HasCallStack => StackPrism a b -> Grammar c a b
fromPrism p = matchPure (pure . forward p) (backward p)

-- | A 'pure' grammar that expects or produces the empty list @[]@.
nil :: HasCallStack => Grammar c t ([a] :- t)
nil = Pure f g
  where
    f t = pure ([] :- t)
    g ([] :- t) = pure t
    g _ = fail "expected []"

-- | A 'pure' grammar that expects or produces a cons ':'.
cons :: HasCallStack => Grammar c (a :- [a] :- t) ([a] :- t)
cons = Pure f g
  where
    f (x :- xs :- t) = pure ((x : xs) :- t)
    g ((x : xs) :- t) = pure (x :- xs :- t)
    g _ = fail "expected (:)"


----------------------------------------------------------------------
-- data Ctx, Grammar

data Ctx = CtxNode | CtxElem | CtxAttrs | CtxAVal | CtxCont
  deriving (Eq, Show, Ord, Enum, Bounded)

type family   XmlValue (c :: Ctx) :: v
type instance XmlValue 'CtxNode  = Node
type instance XmlValue 'CtxElem  = Element
type instance XmlValue 'CtxAttrs = Attrs
type instance XmlValue 'CtxAVal  = AVal
type instance XmlValue 'CtxCont  = ST

type AVal = Maybe ST

data Grammar (ctx :: Ctx) doc val where
  Id :: Grammar ctx t t  -- see 'Category' instance
  (:.) :: Grammar ctx t2 t3 -> Grammar ctx t1 t2 -> Grammar ctx t1 t3  -- see 'Category' instance

  Empty :: Grammar ctx t1 t2  -- see 'Monoid' instance
  (:<>) :: Grammar ctx t1 t2 -> Grammar ctx t1 t2 -> Grammar ctx t1 t2  -- see 'Monoid' instance

  Pure :: (t1 -> Either ST v) -> (t2 -> Maybe t1) -> Grammar ctx t1 t2
  Many :: Grammar ctx t t -> Grammar ctx t t

  Node :: Grammar 'CtxElem (Element :- t1) t2
       -> Grammar 'CtxCont (ST :- t1) t2
       -> Grammar 'CtxNode t1 t2

  Elem :: PName
       -> Grammar 'CtxAttrs t1 t2
       -> Grammar 'CtxNode t2 t3
       -> Grammar 'CtxElem (Element :- t1) t3

  Attr :: PName
       -> Grammar 'CtxAVal (AVal :- t1) t2
       -> Grammar 'CtxAttrs t1 t2

  Cont :: Grammar 'CtxCont t1 t2


-- | The '.' operator is the main way to compose two grammars.
instance Category (Grammar (c :: Ctx)) where
  id = Id
  (.) = (:.)

-- | The @Monoid@ instance allows you to denote choice: if the left grammar doesn't succeed, the right grammar is tried.
instance Monoid (Grammar (c :: Ctx) t1 t2) where
  mempty = Empty
  mappend = (:<>)


----------------------------------------------------------------------
-- class IsoXML

class IsoXML (c :: Ctx) a where
  isoXml :: Grammar c (XmlValue c :- t) (a :- t)

instance IsoXML 'CtxAVal Bool   where isoXml = matchRead . matchAVal
instance IsoXML 'CtxAVal Int    where isoXml = matchRead . matchAVal
instance IsoXML 'CtxAVal String where isoXml = matchAVal


----------------------------------------------------------------------
-- language

-- | Creates a pure grammar that doesn't specify any JSON format but just operates on the Haskell
-- level.
matchPure :: HasCallStack => (t1 -> Either ST v) -> (t2 -> Maybe t1) -> Grammar ctx t1 t2
matchPure = Pure

-- | Try to apply a grammar as many times as possible. The argument grammar's output is fed to
-- itself as input until doing so again would fail. This allows you to express repetitive
-- constructions such as array elements.
matchMany :: HasCallStack => Grammar ctx t t -> Grammar ctx t t
matchMany = Many

-- | Match heterogeneous nodes into a '[Node]' on @t2@, like this: @matchMany (cons . matchNode _ _)
-- . nil@.  The return type is not @Grammar 'CtxNode (Node :- t1) t2@, for this would be in the way
-- of using 'matchNode' in list constructions.
matchNode :: HasCallStack
          => Grammar 'CtxElem (Element :- t1) t2
          -> Grammar 'CtxCont (ST :- t1) t2
          -> Grammar 'CtxNode t1 t2
matchNode = Node

matchElem :: HasCallStack
          => PName
          -> Grammar 'CtxAttrs t1 t2
          -> Grammar 'CtxNode t2 t3
          -> Grammar 'CtxElem (Element :- t1) t3
matchElem = Elem

matchAttr :: HasCallStack
          => PName
          -> Grammar 'CtxAVal (AVal :- t1) t2
          -> Grammar 'CtxAttrs t1 t2
matchAttr = Attr

matchCont :: HasCallStack => Grammar 'CtxCont t1 t2
matchCont = Cont


matchRead :: forall v ctx t. (HasCallStack, Show v, Read v) => Grammar ctx (String :- t) (v :- t)
matchRead = matchPure f g
  where
    f (s :- _) = maybe (Left $ "matchRead: " <> cs s) Right . readMaybe @v . cs $ s
    g (v :- t) = Just $ show v :- t

matchAVal :: forall t. HasCallStack => Grammar 'CtxAVal (AVal :- t) (String :- t)
matchAVal = matchPure f g
  where
    f :: (AVal :- t) -> Either ST String
    f (aval :- _) = maybe (Left $ "matchAVal: " <> cs (show aval)) (Right . cs) aval
    g (s :- t) = Just $ Just (cs s) :- t


----------------------------------------------------------------------
-- grammar to render

renderElem :: forall t1 t2. HasCallStack => Grammar 'CtxElem t1 t2 -> t2 -> Maybe t1
renderElem = \case
  Id         -> Just
  g1 :. g2   -> renderElem g1 >=> renderElem g2

  bad@Empty  -> renderFailed "renderElem" bad
  g1 :<> g2  -> \t2 -> renderElem g1 t2 <|> renderElem g2 t2

  Pure _ rdr -> rdr
  Many g     -> manyM (renderElem g)

  Elem nm ga gn -> \(t2 :: t2) -> do
    (children, t3) <- renderNodes gn (mempty, t2)
    (attrs,    t4) <- renderAttrs ga (mempty, t3)
    pure (Element (fromPName nm) attrs children :- t4 :: t1)


renderAttrs :: forall t1 t2. HasCallStack => Grammar 'CtxAttrs t1 t2 -> (Attrs, t2) -> Maybe (Attrs, t1)
renderAttrs = \case
  Id         -> Just
  g1 :. g2   -> renderAttrs g1 >=> renderAttrs g2

  bad@Empty  -> renderFailed "renderAttrs" bad
  g1 :<> g2  -> \val -> renderAttrs g1 val <|> renderAttrs g2 val

  Pure _ rdr -> \(attrs, t) -> (attrs,) <$> rdr t
  Many g     -> manyM (renderAttrs g)

  Attr nm gr -> \(attrs :: Attrs, t2) -> do
    mval :- t1 <- renderAttrVal gr t2
    let attrs' :: Attrs = maybe id (Map.insert $ fromPName nm) mval attrs
    pure (attrs', t1)


renderAttrVal :: forall t1 t2. HasCallStack => Grammar 'CtxAVal t1 t2 -> t2 -> Maybe t1
renderAttrVal = \case
  Id           -> Just
  g1 :. g2     -> renderAttrVal g1 >=> renderAttrVal g2

  bad@Empty    -> renderFailed "renderAttrVal" bad
  g1 :<> g2    -> \val -> renderAttrVal g1 val <|> renderAttrVal g2 val

  Pure _ rdr   -> rdr
  bad@(Many _) -> renderFailed "renderAttrVal/Many" bad  -- FUTUREWORK: allow this?  same attr occuring 0 or more than 2 times?  how does xml work?


renderContent :: forall t1 t2. HasCallStack => Grammar 'CtxCont (ST :- t1) t2 -> t2 -> Maybe (ST :- t1)
renderContent = undefined


renderNodes :: forall t1 t2. HasCallStack => Grammar 'CtxNode t1 t2 -> ([Node], t2) -> Maybe ([Node], t1)
renderNodes = \case
  Id           -> Just
  g1 :. g2     -> renderNodes g1 >=> renderNodes g2

  bad@Empty    -> renderFailed "renderNodes" bad
  g1 :<> g2    -> \val -> renderNodes g1 val <|> renderNodes g2 val

  Pure _ rdr   -> \(nodes, t) -> (nodes,) <$> rdr t
  Many g       -> manyM (renderNodes g)

  Node grel grcnt -> \(nodes :: [Node], t2) -> do
    let runel  = (\(el  :- t) -> NodeElement el  :- t) <$> renderElem    grel  t2
        runcnt = (\(txt :- t) -> NodeContent txt :- t) <$> renderContent grcnt t2
        -- ...
    nd :- t1 <- runel <|> runcnt -- <|> ...
    pure (nd : nodes, t1)


renderFailed :: HasCallStack => String -> grammar -> stack -> Maybe a
renderFailed msg _grammar _stack = trace msg Nothing


----------------------------------------------------------------------
-- grammar to parse

parseElem :: forall t1 t2. HasCallStack => Grammar 'CtxElem t1 t2 -> t1 -> Maybe t2
parseElem _ = undefined

-- Elem case: first parse the attrs, then the nodes.  reverse of render case.

-- FUTUREWORK: ignoreOtherAttrs, ignoreOtherChildren: if we don't add this everywhere, unparsed stuff will
-- throw errors.  perhaps there should be syntactic sugar for where we want this, not sure.  or we
-- refer people who want lenient parsers with no error reporting whatsoever to xml-conduit cursors.
