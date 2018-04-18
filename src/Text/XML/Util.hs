{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Text.XML.Util
where

import Text.XML
import Data.Map as Map
import Data.String.Conversions


type Attrs = Map.Map Name ST


mkDocument :: Element -> Document
mkDocument el = Document defPrologue el defMiscellaneous

defPrologue :: Prologue
defPrologue = Prologue [] Nothing []

defMiscellaneous :: [Miscellaneous]
defMiscellaneous = []
