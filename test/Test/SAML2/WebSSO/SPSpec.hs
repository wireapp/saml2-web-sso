{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.SAML2.WebSSO.SPSpec (spec) where

import Control.Concurrent.MVar
import Data.List.NonEmpty (NonEmpty((:|)))
import Lens.Micro
import SAML2.WebSSO
import SAML2.WebSSO.API.Example
import Test.Hspec
import TestSP
import URI.ByteString.QQ

import qualified Data.Map as Map
import qualified Samples


instance HasConfig IO where
  type ConfigExtra IO = ()
  getConfig = configIO

instance SP IO

instance SPStore IO where
  storeRequest = undefined
  checkAgainstRequest = undefined
  storeAssertion = undefined


----------------------------------------------------------------------
-- tests

spec :: Spec
spec = describe "SP" $ do
  describe "just making sure..." $ do
    describe "instance Ord Time works" $ do
      it "ago <  now" $ (timeLongAgo <  timeNow) `shouldBe` True
      it "ago <= now" $ (timeLongAgo <= timeNow) `shouldBe` True
      it "now <= now" $ (timeNow     <= timeNow) `shouldBe` True

  specSimpleSP
  specJudgeT
  specExecuteVerdict


specSimpleSP :: Spec
specSimpleSP = describe "SimpleSP" $ do
-- TODO: test SimpleSP a lot better.

  describe "simpleStoreRequest" $ do
    it "stores requests" $ do
      store <- newMVar mempty
      simpleStoreRequest store (ID "3") timeNow `shouldReturn` ()
      (Map.toList <$> readMVar store) `shouldReturn` [(ID "3", timeNow)]

  describe "simpleCheckAgainstRequest" $ do
    context "end-of-life has not been reached" $ do
      it "finds stored request" $ do
        store <- newMVar (Map.fromList [(ID "3", timeIn10minutes)])
        simpleCheckAgainstRequest store (ID "3") timeNow `shouldReturn` True

    context "end-of-life has been reached" $ do
      it "does not find stored request" $ do
        store <- newMVar (Map.fromList [(ID "3", timeLongAgo)])
        simpleCheckAgainstRequest store (ID "3") timeNow `shouldReturn` False

    context "request is not stored" $ do
      it "does not find stored request" $ do
        store <- newMVar mempty
        simpleCheckAgainstRequest store (ID "3") timeNow `shouldReturn` False

  describe "simpleStoreAssertion" $ do
    context "id is new" $ do
      let mkstore = newMVar mempty

      it "stores id" $ do
        store <- mkstore
        _ <- simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes
        takeMVar store `shouldReturn` Map.fromList [(ID "phoo", timeIn10minutes)]

      it "returns True" $ do
        store <- mkstore
        simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes `shouldReturn` True

    context "id is already in the map, but life time is exceeded" $ do
      let mkstore = newMVar (Map.fromList [(ID "phoo", timeLongAgo)])

      it "stores id" $ do
        store <- mkstore
        _ <- simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes
        takeMVar store `shouldReturn` Map.fromList [(ID "phoo", timeIn10minutes)]

      it "returns True" $ do
        store <- mkstore
        simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes `shouldReturn` True

    context "id is already in the map and still alive" $ do
      let mkstore = newMVar (Map.fromList [(ID "phoo", timeIn20minutes)])

      it "keeps map unchanged" $ do
        store <- mkstore
        _ <- simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes
        takeMVar store `shouldReturn` Map.fromList [(ID "phoo", timeIn20minutes)]

      it "returns False" $ do
        store <- mkstore
        simpleStoreAssertion store timeNow (ID "phoo") timeIn10minutes `shouldReturn` False


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

        jctx = JudgeCtx [uri|http://anythingreally.com/|]  -- TODO: this only "works" out because we
                                                           -- expect the judgements to be forbiden;
                                                           -- but now the "forbidden" is for the
                                                           -- wrong reasons.  we also need to test
                                                           -- that a good response with this jctx
                                                           -- actually passes.

    it "violate condition not-before" $ do
      testCtx2 <- mkTestCtx2
      verdict <- ioFromTestSP (testCtx2 & ctxNow .~ timeLongAgo) $ judge resp jctx
      isDenied verdict

    it "violate condition not-on-or-after" $ do
      testCtx2 <- mkTestCtx2
      verdict <- ioFromTestSP (testCtx2 & ctxNow .~ timeIn20minutes) $ judge resp jctx
      isDenied verdict

    it "satisfy all conditions" $ do
      testCtx3 <- mkTestCtx3
      pendingWith "we may test this in spar already (need to check)"
      -- invalid InResponseTo field: ID {renderID = \"id05873dd012c44e6db0bd59f5aa2e6a0a\"}","
      -- Assertion IssueInstant in the future: \"2018-04-13T06:33:02.743Z\"",
      -- "bearer-confirmed assertions must be audience-restricted.",
      -- "AuthnStatement IssueInstance in the future: \"2018-03-27T06:23:57.851Z\""]}

      isGranted =<< ioFromTestSP testCtx3 (judge resp jctx)
      isGranted =<< ioFromTestSP (testCtx3 & ctxNow .~ timeIn10minutes) (judge resp jctx)

    it "status failure" $ do
      testCtx2 <- mkTestCtx2
      verdict <- ioFromTestSP testCtx2 $ judge (resp & rspStatus .~ statusFailure) jctx
      isDenied verdict

    it "status success" $ do
      testCtx2 <- mkTestCtx2
      verdict <- ioFromTestSP testCtx2 $ judge (resp & rspStatus .~ statusSuccess) jctx
      pendingWith "we may test this in spar already (need to check)"
      -- "invalid InResponseTo field: ID {renderID = \"id05873dd012c44e6db0bd59f5aa2e6a0a\"}"
      -- "Issuerinstant in the future: \"2018-03-11T17:13:13Z\""
      -- "Assertion IssueInstant in the future: \"2018-04-13T06:33:02.743Z\""
      -- "bearer-confirmed assertions must be audience-restricted."
      -- "AuthnStatement IssueInstance in the future: \"2018-03-27T06:23:57.851Z\""

      isGranted verdict

    it "status success yields name, nick" $ do
      testCtx2 <- mkTestCtx2
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
