{-# LANGUAGE OverloadedStrings #-}

-- | WARNING: these optics make assumptions about the shape of the AuthnResponse that are not valid
-- in general!  (they are useful for testing, though.)
module SAML2.WebSSO.Test.Lenses where

import Control.Lens
import Data.List.NonEmpty as NL
import SAML2.WebSSO
import Test.QuickCheck.Instances ()


_nlhead :: Lens' (NonEmpty a) a
_nlhead f (a :| as) = (:| as) <$> f a

assertionL :: Lens' AuthnResponse Assertion
assertionL = rspPayload . _nlhead

conditionsL :: Traversal' AuthnResponse Conditions
conditionsL = assertionL . assConditions . _Just

subjL :: Lens' AuthnResponse Subject
subjL = assertionL . assContents . sasSubject

scdataL :: Traversal' AuthnResponse SubjectConfirmationData
scdataL = subjL . subjectConfirmations . ix 0 . scData . _Just

statementL :: Lens' AuthnResponse Statement
statementL = assertionL . assContents . sasStatements . _nlhead

userRefL :: Getter AuthnResponse UserRef
userRefL = to $ \aresp ->
  let tenant  = aresp ^. assertionL . assIssuer
      subject = aresp ^. subjL . subjectID
  in UserRef tenant subject
