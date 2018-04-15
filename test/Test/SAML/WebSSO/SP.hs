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

module Test.SAML.WebSSO.SP (tests) where

import Control.Monad.State
import Lens.Micro
import Lens.Micro.TH
import Test.Tasty
import Test.Tasty.HUnit

import qualified Test.Samples
import SAML.WebSSO


----------------------------------------------------------------------
-- test service provider

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

instance SP TestSP where
  logger :: String -> TestSP ()
  logger _ = pure ()

  getNow :: TestSP Time
  getNow = gets (^. ctxNow)


testSP :: Ctx -> TestSP a -> IO a
testSP ctx m = evalStateT m ctx


----------------------------------------------------------------------
-- tests

tests :: TestTree
tests = testGroup "SP"
  [ testGroup "just making sure..."
    [ testCase "instance Ord Time works" $ do
        assertBool "ago <  now" (timeLongAgo <  timeNow)
        assertBool "ago <= now" (timeLongAgo <= timeNow)
        assertBool "now <= now" (timeNow     <= timeNow)
    ]

  , testGroup "JudgetT"
    [ testCase "no msgs" $ do
        verdict <- runJudgeT $ do
          pure $ AccessGranted "" ""
        assertEqual (show verdict) verdict (AccessGranted "" "")

    , testCase "1 msg" $ do
        verdict <- runJudgeT $ do
          deny ["wef"]
          pure $ AccessGranted "" ""
        assertEqual (show verdict) verdict (AccessDenied ["wef"])

    , testCase "2 msg" $ do
        verdict <- runJudgeT $ do
          deny ["wef"]
          deny ["phoo", "gna"]
          pure $ AccessGranted "" ""
        assertEqual (show verdict) verdict (AccessDenied ["wef", "phoo", "gna"])

    , testCase "1 msg, then giveup, then send another message" $ do
        verdict <- runJudgeT $ do
          deny ["wef"]
          () <- giveup ["eeek"]
          deny ["phoo"]
          pure $ AccessGranted "" ""
        assertEqual (show verdict) verdict (AccessDenied ["wef", "eeek"])
    ]

  , let resp = Test.Samples.microsoft_authnresponse_1
               & rspPayload . ix 0 . assConditions . _Just . condNotBefore    .~ Just timeNow
               & rspPayload . ix 0 . assConditions . _Just . condNotOnOrAfter .~ Just timeIn20minutes

        isGranted verdict = assertBool (show verdict) $ case verdict of AccessGranted{} -> True; _ -> False
        isDenied  verdict = assertBool (show verdict) $ case verdict of AccessDenied{}  -> True; _ -> False

    in testGroup "judge"
    [ testCase "violate condition not-before" $ do
        verdict <- testSP (defaultCtx & ctxNow .~ timeLongAgo) $ judge resp
        isDenied verdict

    , testCase "violate condition not-on-or-after" $ do
        verdict <- testSP (defaultCtx & ctxNow .~ timeIn20minutes) $ judge resp
        isDenied verdict

    , testCase "satisfy all conditions" $ do
        isGranted =<< testSP defaultCtx (judge resp)
        isGranted =<< testSP (defaultCtx & ctxNow .~ timeIn10minutes) (judge resp)

    , testCase "status failure" $ do
        verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusFailure "donno")
        isDenied verdict

    , testCase "status success" $ do
        verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusSuccess)
        isGranted verdict

    , testCase "status success yields name, nick" $ do
        verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusSuccess)
        assertEqual (show verdict) (AccessGranted "fisxt1@azurewire.onmicrosoft.com" "fisxt1") verdict

    -- check the rest of the AuthnResponse type: what do we have to take into account?  what can we
    -- delete?  keeping values parsed and enforce some default where we don't need to do anything
    -- helps with future extensions.

    ]

  , testGroup "executeVerdict"
    [ testCase "..." $ do
        pure ()
    ]
  ]
