{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE InstanceSigs         #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE RankNTypes           #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE ViewPatterns         #-}

module TestSP where

import Control.Monad.State
import Lens.Micro
import Lens.Micro.TH

import SAML.WebSSO


data Ctx = Ctx
  { _ctxNow :: Time
  }
  deriving (Eq, Show)

makeLenses ''Ctx

defaultCtx :: Ctx
defaultCtx = Ctx
  { _ctxNow = timeNow
  }


timeLongAgo     :: Time
timeLongAgo     = unsafeReadTime "1918-04-14T09:58:58.457Z"

timeNow         :: Time
timeNow         = unsafeReadTime "2018-03-11T17:13:13Z"

timeIn10minutes :: Time
timeIn10minutes = unsafeReadTime "2018-03-11T17:23:00.01Z"

timeIn20minutes :: Time
timeIn20minutes = unsafeReadTime "2018-03-11T17:33:00Z"


type TestSP = StateT Ctx IO

instance HasConfig TestSP where
  getConfig = pure undefined

instance SP TestSP where
  logger :: String -> TestSP ()
  logger _ = pure ()

  getNow :: TestSP Time
  getNow = gets (^. ctxNow)


testSP :: Ctx -> TestSP a -> IO a
testSP ctx m = evalStateT m ctx
