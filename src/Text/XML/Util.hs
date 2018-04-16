{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Text.XML.Util
where

import Text.XML


mkDocument :: Element -> Document
mkDocument el = Document defPrologue el defMiscellaneous

defPrologue :: Prologue
defPrologue = Prologue [] Nothing []

defMiscellaneous :: [Miscellaneous]
defMiscellaneous = []
