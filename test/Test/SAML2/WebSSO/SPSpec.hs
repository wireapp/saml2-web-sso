{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.SAML2.WebSSO.SPSpec (spec) where

import Control.Concurrent.MVar
import Control.Lens
import Data.List.NonEmpty (NonEmpty((:|)))
import SAML2.WebSSO
import SAML2.WebSSO.API.Example (AssertionStore)
import Test.Hspec
import URI.ByteString.QQ
import Util

import qualified Data.Map as Map
import qualified Samples


instance HasConfig IO where
  getConfig = configIO

instance HasLogger IO
instance HasCreateUUID IO
instance HasNow IO

instance SPStoreID any IO where
  storeID   = undefined
  unStoreID = undefined
  isAliveID = undefined


----------------------------------------------------------------------
-- tests

spec :: Spec
spec = describe "SP" $ do
  describe "just making sure..." $ do
    describe "instance Ord Time works" $ do
      it "ago <  now" $ (timeLongAgo <  timeNow) `shouldBe` True
      it "ago <= now" $ (timeLongAgo <= timeNow) `shouldBe` True
      it "now <= now" $ (timeNow     <= timeNow) `shouldBe` True

  specStoreAssertion
  specJudgeT
  specExecuteVerdict


specStoreAssertion :: Spec
specStoreAssertion = describe "storeAssertion" . before mkTestCtxSimple $ do
    let peek :: CtxV -> IO AssertionStore
        peek ctx = ((^. ctxAssertionStore) <$> readMVar ctx)

    context "id is new" $ do
      it "stores id and returns True" $ \ctx -> do
        ioFromTestSP ctx (storeAssertion (ID "phoo") timeIn10minutes)
          `shouldReturn` True
        peek ctx
          `shouldReturn` Map.fromList [(ID "phoo", timeIn10minutes)]

    context "id is already in the map, but life time is exceeded" $ do
      it "stores id and returns True" $ \ctx -> do
        _ <- ioFromTestSP ctx $ storeAssertion (ID "phoo") timeLongAgo  -- warmup
        ioFromTestSP ctx (storeAssertion (ID "phoo") timeIn10minutes)
          `shouldReturn` True
        peek ctx
          `shouldReturn` Map.fromList [(ID "phoo", timeIn10minutes)]

    context "id is already in the map and still alive" $ do
      it "keeps map unchanged and returns False" $ \ctx -> do
        _ <- ioFromTestSP ctx $ storeAssertion (ID "phoo") timeIn20minutes  -- warmup
        bef <- peek ctx
        ioFromTestSP ctx (storeAssertion (ID "phoo") timeIn10minutes)
          `shouldReturn` False
        aft <- peek ctx
        bef
          `shouldBe` aft


specJudgeT :: Spec
specJudgeT = do
  describe "JudgeT" $ do
    let emptyUserID = UserRef (Issuer [uri|http://example.com/|]) (opaqueNameID "me")

    it "no msgs" $ do
      verdict <- runJudgeT undefined $ pure $ AccessGranted (UserRef (Issuer [uri|http://example.com/|]) (opaqueNameID "me"))
      verdict `shouldBe` AccessGranted emptyUserID

    it "1 msg" $ do
      verdict <- runJudgeT undefined $ do
        deny ["wef"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef"]

    it "2 msg" $ do
      verdict <- runJudgeT undefined $ do
        deny ["wef"]
        deny ["phoo", "gna"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef", "phoo", "gna"]

    it "1 msg, then giveup, then send another message" $ do
      verdict <- runJudgeT undefined $ do
        deny ["wef"]
        () <- giveup ["eeek"]
        deny ["phoo"]
        pure $ AccessGranted emptyUserID
      verdict `shouldBe` AccessDenied ["wef", "eeek"]

  describe "judge" $ do
    let resp = Samples.microsoft_authnresponse_1
               & rspIssueInstant .~ timeNow
               & rspPayload . _nlhead . assConditions . _Just . condNotBefore    .~ Just timeNow
               & rspPayload . _nlhead . assConditions . _Just . condNotOnOrAfter .~ Just timeIn20minutes

        _nlhead :: Lens' (NonEmpty a) a
        _nlhead f (a :| as) = (:| as) <$> f a

        isGranted :: HasCallStack => AccessVerdict -> Expectation
        isGranted = (`shouldSatisfy` (\case AccessGranted{} -> True; _ -> False))

        isDenied :: HasCallStack => AccessVerdict -> Expectation
        isDenied = (`shouldSatisfy` (\case AccessDenied{} -> True; _ -> False))

        jctx = JudgeCtx (Issuer [uri|http://anythingreally.com/|]) [uri|http://anythingreally.com/|]
                                                           -- TODO: this only "works" out because we
                                                           -- expect the judgements to be forbiden;
                                                           -- but now the "forbidden" is for the
                                                           -- wrong reasons.  we also need to test
                                                           -- that a good response with this jctx
                                                           -- actually passes.

    it "violate condition not-before" $ do
      ctx <- mkTestCtxWithIdP
      modifyMVar_ ctx $ pure . (ctxNow .~ timeLongAgo)
      verdict <- ioFromTestSP ctx $ judge resp jctx
      isDenied verdict

    it "violate condition not-on-or-after" $ do
      ctx <- mkTestCtxWithIdP
      modifyMVar_ ctx $ pure . (ctxNow .~ timeIn20minutes)
      verdict <- ioFromTestSP ctx $ judge resp jctx
      isDenied verdict

    it "satisfy all conditions" $ do
      pendingWith "we may test this in spar already (need to check)"
      -- testCtx3 <- mkTestCtx3
      -- invalid InResponseTo field: ID {renderID = \"id05873dd012c44e6db0bd59f5aa2e6a0a\"}","
      -- Assertion IssueInstant in the future: \"2018-04-13T06:33:02.743Z\"",
      -- "bearer-confirmed assertions must be audience-restricted.",
      -- "AuthnStatement IssueInstance in the future: \"2018-03-27T06:23:57.851Z\""]}

      -- isGranted =<< ioFromTestSP testCtx3 (judge resp jctx)
      -- isGranted =<< ioFromTestSP (testCtx3 & ctxNow .~ timeIn10minutes) (judge resp jctx)

    it "status failure" $ do
      testCtx2 <- mkTestCtxWithIdP
      verdict <- ioFromTestSP testCtx2 $ judge (resp & rspStatus .~ statusFailure) jctx
      isDenied verdict

    it "status success" $ do
      testCtx2 <- mkTestCtxWithIdP
      verdict <- ioFromTestSP testCtx2 $ judge (resp & rspStatus .~ statusSuccess) jctx
      pendingWith "we may test this in spar already (need to check)"
      -- "invalid InResponseTo field: ID {renderID = \"id05873dd012c44e6db0bd59f5aa2e6a0a\"}"
      -- "Issuerinstant in the future: \"2018-03-11T17:13:13Z\""
      -- "Assertion IssueInstant in the future: \"2018-04-13T06:33:02.743Z\""
      -- "bearer-confirmed assertions must be audience-restricted."
      -- "AuthnStatement IssueInstance in the future: \"2018-03-27T06:23:57.851Z\""

      isGranted verdict

    it "status success yields name, nick" $ do
      testCtx2 <- mkTestCtxWithIdP
      verdict <- ioFromTestSP testCtx2 $ judge (resp & rspStatus .~ statusSuccess) jctx
      let uid = UserRef (Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|])
                       (opaqueNameID "E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84")
      pendingWith "we may test this in spar already (need to check)"
      -- "invalid InResponseTo field: ID {renderID = \"id05873dd012c44e6db0bd59f5aa2e6a0a\"}"
      -- "Issuer instant in the future: \"2018-03-11T17:13:13Z\""
      -- "Assertion IssueInstant in the future: \"2018-04-13T06:33:02.743Z\""
      -- "bearer-confirmed assertions must be audience-restricted."
      -- "AuthnStatement IssueInstance in the future: \"2018-03-27T06:23:57.851Z\""

      verdict `shouldBe` AccessGranted uid

    -- TODO: check the rest of the AuthnResponse type: what do we have to take into account?  what can we
    -- delete?  keeping values parsed and enforce some default where we don't need to do anything
    -- helps with future extensions.


specExecuteVerdict :: Spec
specExecuteVerdict =
  describe "executeVerdict" $ do
    it "..." pending


-- TODO: prop test: generate authnresponse and judge it.  both accept and denied are acceptable
-- results, but this will catch errors like crashes.
