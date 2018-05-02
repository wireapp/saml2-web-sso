{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DefaultSignatures     #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE ViewPatterns          #-}

module SAML.WebSSO.SP where

import Control.Lens  -- TODO: use Lens.Micro, but that doesn't appear to have view?!
import Control.Monad.IO.Class
import Control.Monad.Writer
import Control.Monad.Except
import Data.Foldable (toList)
import Data.Maybe
import Data.String.Conversions
import Data.Time
import Data.UUID (UUID)
import GHC.Stack
import Network.HTTP.Types.Header
import Servant.Server
import URI.ByteString

import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID

import SAML.WebSSO.Config
import SAML.WebSSO.Types
import SAML.WebSSO.XML


-- | Application logic of the service provider.
class Monad m => SP m where
  logger :: String -> m ()
  default logger :: MonadIO m => String -> m ()
  logger = liftIO . putStrLn

  createUUID :: m UUID
  default createUUID :: MonadIO m => m UUID
  createUUID = liftIO UUID.nextRandom

  getNow :: m Time
  default getNow :: MonadIO m => m Time
  getNow = Time <$> liftIO getCurrentTime

-- | HTTP handling of the service provider.
class SP m => SPNT m where
  nt :: forall x. m x -> Handler x
  default nt :: m ~ Handler => (forall x. m x -> Handler x)
  nt = id

  redirect :: URI -> [Header] -> m void
  default redirect :: m ~ Handler => URI -> [Header] -> m void
  redirect uri extra = throwError err302 { errHeaders = ("Location", cs $ renderURI uri) : extra }

  reject :: m void
  default reject :: m ~ Handler => m void
  reject = throwError err403

instance SP IO
instance SP Handler
instance SPNT Handler


----------------------------------------------------------------------
-- combinators

-- | Microsoft Active Directory requires IDs to be of the form @id<32 hex digits>@, so the
-- @UUID.toText@ needs to be tweaked a little.
createID :: SP m => m ID
createID = ID . fixMSAD . UUID.toText <$> createUUID
  where
    fixMSAD :: ST -> ST
    fixMSAD = cs . ("id" <>) . filter (/= '-') . cs

createAuthnRequest :: SP m => m AuthnRequest
createAuthnRequest = do
  x0 <- createID
  let x1 = config ^. cfgVersion
  x2 <- getNow
  let x3 = NameID $ getPath' SsoPathAuthnResp

  pure AuthnRequest
    { _rqID               = x0 :: ID
    , _rqVersion          = x1 :: Version
    , _rqIssueInstant     = x2 :: Time
    , _rqIssuer           = x3 :: NameID
    , _rqDestination      = Nothing
    }


----------------------------------------------------------------------
-- compute access verdict(s)

-- | This monad collects errors in a writer, so that the reasons for access denial are as helpful as
-- possible.  It is a little like an exception monad, except you can throw several exceptions
-- without interrupting the flow, and will get a list of them at the end.
--
-- NOTE: @-XGeneralizedNewtypeDeriving@ does not help with the boilerplate instances below, since
-- this is a transformer stack and not a concrete 'Monad'.
newtype JudgeT m a = JudgeT { fromJudgeT :: ExceptT [ST] (WriterT [ST] m) a }

runJudgeT :: forall m. (Monad m, SP m) => JudgeT m AccessVerdict -> m AccessVerdict
runJudgeT (JudgeT em) = fmap collectErrors . runWriterT $ runExceptT em
  where
    collectErrors :: (Either [ST] AccessVerdict, [ST]) -> AccessVerdict
    collectErrors (Left errs, errs')    = AccessDenied $ errs' <> errs
    collectErrors (Right _, errs@(_:_)) = AccessDenied errs
    collectErrors (Right v, [])         = v

-- the parts of the MonadError, MonadWriter interfaces we want here.
class (Functor m, Applicative m, Monad m) => MonadJudge m where
  deny :: [ST] -> m ()
  giveup :: [ST] -> m a

instance (Functor m, Applicative m, Monad m) => MonadJudge (JudgeT m) where
  deny = JudgeT . tell
  giveup = JudgeT . throwError

instance (Functor m, Applicative m, Monad m) => Functor (JudgeT m) where
  fmap f = JudgeT . fmap f . fromJudgeT

instance (Functor m, Applicative m, Monad m) => Applicative (JudgeT m) where
  pure = JudgeT . pure
  (JudgeT f) <*> (JudgeT x) = JudgeT (f <*> x)

instance (Functor m, Applicative m, Monad m) => Monad (JudgeT m) where
  (JudgeT x) >>= f = JudgeT (x >>= fromJudgeT . f)

instance SP m => SP (JudgeT m) where
  logger     = JudgeT . lift . lift . logger
  createUUID = JudgeT . lift . lift $ createUUID
  getNow     = JudgeT . lift . lift $ getNow


judge :: (SP m) => AuthnResponse -> m AccessVerdict
judge resp = runJudgeT (judge' resp)

judge' :: (HasCallStack, MonadJudge m, SP m) => AuthnResponse -> m AccessVerdict
judge' resp = do
  -- if any assertion has any violated conditions, you get 'AccessDenied'.
  judgeConditions `mapM_` catMaybes (view assConditions <$> resp ^. rspPayload)

  -- status must be success.
  case resp ^. rspStatus of
    StatusSuccess -> pure ()
    bad -> deny ["status: " <> cs (show bad)]

  case resp ^. rspPayload of
    [ass] -> case ass ^. assContents of
      SubjectAndStatements _subj (toList -> stmts) -> do
        checkAuthnStatement stmts
        let attrs = getAttributeStatements stmts
            nameKey = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
            nickKey = "http://schemas.microsoft.com/identity/claims/displayname"  -- TODO: don't use this field?
        AccessGranted <$> requireAttributeText nameKey attrs
                      <*> requireAttributeText nickKey attrs

    []                           -> giveup ["no assertions"]
    _:_                          -> giveup ["not supported: more than one assertion"]

  -- TODO: 'judge' must only accept 'AuthResponse' values wrapped in 'SignaturesVerified', which can
  -- only be constructed by "Text.XML.DSig".

  -- TODO: [3/4.1.4.2] AuthnStatement must be present!  Subject must be present!  also other requirements!

  -- TODO: in case of error, log response (would xml be better?) and SP context for extraction of
  -- failing test cases in case of prod failures.


checkAuthnStatement :: MonadJudge m => [Statement] -> m ()
checkAuthnStatement = mapM_ go
  where
    go (AuthnStatement _ _ Nothing Nothing) = pure ()
    go (bad@AuthnStatement{})               = giveup ["bad AuthnStatement: " <> cs (show bad)]
    go _                                    = pure ()


getAttributeStatements :: [Statement] -> [Attribute]
getAttributeStatements = mconcat . fmap go
  where
    go (AttributeStatement as) = toList as
    go _                       = []


requireAttributeText :: MonadJudge m => ST -> [Attribute] -> m ST
requireAttributeText key as = case filter ((== key) . (^. stattrName)) as of
  [(^. stattrValues) -> [val]] -> case val of AttributeValueText txt -> pure txt
  []                           -> giveup ["attribute not found: " <> key]
  bad@(_:_)                    -> giveup ["attribute not found more than once: " <> cs (show (key, bad))]


judgeConditions :: (HasCallStack, MonadJudge m, SP m) => Conditions -> m ()
judgeConditions (Conditions lowlimit uplimit onetimeonly) = do
  now <- getNow
  deny ["violation of NotBefore condition"    | maybe False (now <)  lowlimit]
  deny ["violation of NotOnOrAfter condition" | maybe False (now >=) uplimit]
  deny ["unsupported flag: OneTimeUse" | onetimeonly]


----------------------------------------------------------------------
-- to be used in the future?

getIdPMeta :: SP m => m ()
getIdPMeta = undefined

getUser :: SP m => String -> m ()
getUser = undefined
