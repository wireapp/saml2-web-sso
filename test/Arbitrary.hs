{-# LANGUAGE OverloadedStrings #-}

module Arbitrary where

import Data.String.Conversions
import Hedgehog
import SAML.WebSSO
import URI.ByteString

import qualified Data.Text as ST
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range


genVersion :: Gen Version
genVersion = Gen.enumBounded

genURI :: Gen URI
genURI = either (error . show) pure $ parseURI' "http://wire.com/"

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
