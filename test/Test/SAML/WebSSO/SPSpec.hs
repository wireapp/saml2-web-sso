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

module Test.SAML.WebSSO.SPSpec (spec) where

import Control.Monad.State
import Lens.Micro
import Lens.Micro.TH
import Test.Hspec

import qualified Samples
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

spec :: Spec
spec = describe "SP" $ do
  describe "just making sure..." $ do
    describe "instance Ord Time works" $ do
      it "ago <  now" $ (timeLongAgo <  timeNow) `shouldBe` True
      it "ago <= now" $ (timeLongAgo <= timeNow) `shouldBe` True
      it "now <= now" $ (timeNow     <= timeNow) `shouldBe` True

  describe "JudgetT" $ do
    it "no msgs" $ do
      verdict <- runJudgeT $ pure $ AccessGranted (UserId "" "")
      verdict `shouldBe` AccessGranted (UserId "" "")

    it "1 msg" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        pure $ AccessGranted (UserId "" "")
      verdict `shouldBe` AccessDenied ["wef"]

    it "2 msg" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        deny ["phoo", "gna"]
        pure $ AccessGranted (UserId "" "")
      verdict `shouldBe` AccessDenied ["wef", "phoo", "gna"]

    it "1 msg, then giveup, then send another message" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        () <- giveup ["eeek"]
        deny ["phoo"]
        pure $ AccessGranted (UserId "" "")
      verdict `shouldBe` AccessDenied ["wef", "eeek"]

  describe "judge" $ do
    let resp = Samples.microsoft_authnresponse_1
               & rspPayload . ix 0 . assConditions . _Just . condNotBefore    .~ Just timeNow
               & rspPayload . ix 0 . assConditions . _Just . condNotOnOrAfter .~ Just timeIn20minutes

        isGranted verdict = (case verdict of AccessGranted{} -> True; _ -> False) `shouldBe` True
        isDenied  verdict = (case verdict of AccessDenied{}  -> True; _ -> False) `shouldBe` True

    it "violate condition not-before" $ do
      verdict <- testSP (defaultCtx & ctxNow .~ timeLongAgo) $ judge resp
      isDenied verdict

    it "violate condition not-on-or-after" $ do
      verdict <- testSP (defaultCtx & ctxNow .~ timeIn20minutes) $ judge resp
      isDenied verdict

    it "satisfy all conditions" $ do
      isGranted =<< testSP defaultCtx (judge resp)
      isGranted =<< testSP (defaultCtx & ctxNow .~ timeIn10minutes) (judge resp)

    it "status failure" $ do
      verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusFailure "donno")
      isDenied verdict

    it "status success" $ do
      verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusSuccess)
      isGranted verdict

    it "status success yields name, nick" $ do
      verdict <- testSP defaultCtx $ judge (resp & rspStatus .~ StatusSuccess)
      let uid = UserId "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/" "E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84"
      verdict `shouldBe` AccessGranted uid

    -- check the rest of the AuthnResponse type: what do we have to take into account?  what can we
    -- delete?  keeping values parsed and enforce some default where we don't need to do anything
    -- helps with future extensions.

  describe "executeVerdict" $ do
    it "..." pending
