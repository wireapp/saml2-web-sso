{-# LANGUAGE OverloadedStrings #-}

module Test.SAML2.WebSSO.SPSpec (spec) where

import Lens.Micro
import SAML2.WebSSO
import Test.Hspec
import TestSP

import qualified Samples


instance HasConfig IO where
  getConfig = configIO

instance SP IO


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
    let emptyUserID = UserId (mkIssuer "http://example.com/") (opaqueNameID "me")

    it "no msgs" $ do
      verdict <- runJudgeT $ pure $ AccessGranted (UserId (mkIssuer "http://example.com/") (opaqueNameID "me"))
      verdict `shouldBe` AccessGranted emptyUserID

    it "1 msg" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef"]

    it "2 msg" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        deny ["phoo", "gna"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef", "phoo", "gna"]

    it "1 msg, then giveup, then send another message" $ do
      verdict <- runJudgeT $ do
        deny ["wef"]
        () <- giveup ["eeek"]
        deny ["phoo"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef", "eeek"]

  describe "judge" $ do
    let resp = Samples.microsoft_authnresponse_1
               & rspPayload . ix 0 . assConditions . _Just . condNotBefore    .~ Just timeNow
               & rspPayload . ix 0 . assConditions . _Just . condNotOnOrAfter .~ Just timeIn20minutes

        isGranted verdict = (case verdict of AccessGranted{} -> True; _ -> False) `shouldBe` True
        isDenied  verdict = (case verdict of AccessDenied{}  -> True; _ -> False) `shouldBe` True

    it "violate condition not-before" $ do
      testCtx2 <- mkTestCtx2
      verdict <- testSP (testCtx2 & ctxNow .~ timeLongAgo) $ judge resp
      isDenied verdict

    it "violate condition not-on-or-after" $ do
      testCtx2 <- mkTestCtx2
      verdict <- testSP (testCtx2 & ctxNow .~ timeIn20minutes) $ judge resp
      isDenied verdict

    it "satisfy all conditions" $ do
      testCtx2 <- mkTestCtx2
      isGranted =<< testSP testCtx2 (judge resp)
      isGranted =<< testSP (testCtx2 & ctxNow .~ timeIn10minutes) (judge resp)

    it "status failure" $ do
      testCtx2 <- mkTestCtx2
      verdict <- testSP testCtx2 $ judge (resp & rspStatus .~ StatusFailure "donno")
      isDenied verdict

    it "status success" $ do
      testCtx2 <- mkTestCtx2
      verdict <- testSP testCtx2 $ judge (resp & rspStatus .~ StatusSuccess)
      isGranted verdict

    it "status success yields name, nick" $ do
      testCtx2 <- mkTestCtx2
      verdict <- testSP testCtx2 $ judge (resp & rspStatus .~ StatusSuccess)
      let uid = UserId (mkIssuer "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/")
                       (opaqueNameID "E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84")
      verdict `shouldBe` AccessGranted uid

    -- check the rest of the AuthnResponse type: what do we have to take into account?  what can we
    -- delete?  keeping values parsed and enforce some default where we don't need to do anything
    -- helps with future extensions.

  describe "executeVerdict" $ do
    it "..." pending
