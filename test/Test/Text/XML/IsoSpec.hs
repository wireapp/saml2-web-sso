{-# LANGUAGE ConstraintKinds       #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DefaultSignatures     #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE ViewPatterns          #-}

module Test.Text.XML.IsoSpec (spec) where

import Control.Category (Category(..))
import Control.Monad
import Data.Char (toLower)
import Data.Maybe
import Data.StackPrism
import Data.StackPrism.TH
import Data.String
import Data.String.Conversions
import Hedgehog
import Prelude hiding (id, (.))
import Test.Hspec
import Text.XML

import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import Util
import Arbitrary
import Text.XML.Iso
import Text.XML.Util


-- TODO: ElemUniq, ElemsMany1, ElemsMany0, OnlyElems; similarly for Attr*

-- TODO: error handling 0: figure out how to Show stacks and grammars.  we don't have to show everything, just the stuff that's easy.

-- TODO: error handling 1: turn Maybe into Either ST.

-- TODO: error handling 2: make 'Pure' take a proper @MonadXmlParse m => m@, not the silly @Either ST@.

-- TODO: CtxAttrVal for parsing attribute values from string to something more helpful (?)

-- TODO: we may need a dynamic Grammar context next to the stack as well, for name spaces and whatnot.

-- TODO: CtxDocument?


----------------------------------------------------------------------
-- example types

data Prod = Prod Int String
  deriving (Eq, Show)

data Sum = SumX Prod | SumY Bool
  deriving (Eq, Show)

deriveStackPrismsWith (fmap toLower) ''Prod
deriveStackPrismsWith (fmap toLower) ''Sum

instance IsoXML 'CtxElem Prod where
  isoXml = fromPrism prod . matchElem "Prod" (matchAttr "Number" isoXml . matchAttr "Text" isoXml) id

instance IsoXML 'CtxElem Sum where
  isoXml = fromPrism sumx . isoXml
        <> fromPrism sumy . matchElem "Bool" (matchAttr "val" isoXml) id

instance IsoXML 'CtxElem [Sum] where
  isoXml = matchElem "SL" Id (matchMany (cons . matchNode isoXml undefined) . nil)

-- | A type that does not always encode to an 'Element' node, but sometimes to plain text that will
-- be a 'NodeContent'.
data WillBeContent = WillBeElem Prod | WillBeContent ST
  deriving (Eq, Show)

deriveStackPrismsWith (fmap toLower) ''WillBeContent

instance IsoXML 'CtxElem WillBeContent where
  isoXml = fromPrism willbeelem . isoXml

instance IsoXML 'CtxCont WillBeContent where
  isoXml = fromPrism willbecontent . matchCont

data WBCList = WBCList [WillBeContent]
  deriving (Eq, Show)

deriveStackPrismsWith (fmap toLower) ''WBCList

instance IsoXML 'CtxElem WBCList where
  isoXml = fromPrism wbclist . matchElem "WBCList" id (matchMany (cons . matchNode isoXml isoXml) . nil)


-- TODO: this is interesting: can we still make mistakes by not rendering all data so that when we
-- parse the serialized string back it will give us a different value?


----------------------------------------------------------------------
-- test plumbing

spec :: Spec
spec = describe "IsoXML" $ trips >> examples

trips :: Spec
trips = hedgehog $ checkParallel $$(discover)

mkprop :: forall a. (Eq a, Show a, IsoXML 'CtxElem a) => Gen a -> Property
mkprop gen = property $ forAll gen >>= mktrip

mktrip :: forall a. (Eq a, Show a, IsoXML 'CtxElem a) => a -> PropertyT IO ()
mktrip v = tripping v (enc True) dec

enc :: forall a. (HasCallStack, Eq a, Show a, IsoXML 'CtxElem a) => Bool -> a -> LT
enc pretty = renderText def { rsPretty = pretty } . mkDocument . fromMaybe (error "render has Nothing") . renderXml

dec :: forall a. (Eq a, Show a, IsoXML 'CtxElem a) => LT -> Maybe a
dec = parseXml @a . documentRoot . either (error . show) id . parseText def

_runcase :: forall a. (Eq a, Show a, IsoXML 'CtxElem a) => a -> IO ()
_runcase = recheck 0 (Seed 0 0) . property . mktrip


----------------------------------------------------------------------
-- test case list

examples :: HasCallStack => Spec
examples = do
  it "1" $ shouldBe
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Prod Number=\"3\" Text=\"whoof\"/>"
      (enc False $ Prod 3 "whoof")
  it "2" $ shouldBe
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SL><Bool val=\"False\"/><Prod Number=\"3\" Text=\"whoof\"/></SL>"
      (enc False [SumX (Prod 3 "whoof"), SumY False])

  it "3" $ shouldBe
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Prod Number=\"3\" Text=\"whoof\"/>"
      (enc False $ WillBeElem (Prod 3 "whoof"))
  xit "4" $ shouldBe
      ""
      (enc False $ WillBeContent "this is nice")


----------------------------------------------------------------------
-- generated test cases

_prop_Prod :: Property
_prop_Prod = mkprop genProd

genProd :: Gen Prod
genProd = Prod <$> Gen.int (Range.linear (-100) 100) <*> (cs <$> genNiceWord)
