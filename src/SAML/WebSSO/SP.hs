
{-# OPTIONS_GHC -Wno-orphans #-}

module SAML.WebSSO.SP where

import Control.Monad.Except
import Control.Monad.Writer
import Data.Foldable (toList)
import Data.List
import Data.Maybe
import Data.String.Conversions
import Data.Time
import Data.UUID (UUID)
import GHC.Stack
import Lens.Micro
import Network.HTTP.Types.Header
import Servant.Server
import URI.ByteString

import qualified Data.Map as Map
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID

import SAML.WebSSO.Config
import SAML.WebSSO.Types
import Text.XML.Util


-- | Application logic of the service provider.
class (HasConfig m, Monad m) => SP m where
  logger :: LogLevel -> String -> m ()
  default logger :: MonadIO m => LogLevel -> String -> m ()
  logger atleast msg = do
    cfgsays <- (^. cfgLogLevel) <$> getConfig
    liftIO $ loggerIO cfgsays atleast msg

  createUUID :: m UUID
  default createUUID :: MonadIO m => m UUID
  createUUID = liftIO UUID.nextRandom

  getNow :: m Time
  default getNow :: MonadIO m => m Time
  getNow = Time <$> liftIO getCurrentTime

-- | HTTP handling of the service provider.  TODO: rename to 'SPHandler'?
class (SP m, MonadError ServantErr m) => SPNT m where
  type NT m :: *
  nt :: forall x. NT m -> m x -> Handler x

instance SP IO
instance SP Handler

instance SPNT Handler where
  type NT Handler = ()
  nt :: forall x. () -> Handler x -> Handler x
  nt () = id


instance HasConfig Handler where
  getConfig = liftIO getConfig


----------------------------------------------------------------------
-- combinators

loggerIO :: LogLevel -> LogLevel -> String -> IO ()
loggerIO cfgsays atleast msg = if atleast < cfgsays
  then pure ()
  else putStrLn msg

-- | Microsoft Active Directory requires IDs to be of the form @id<32 hex digits>@, so the
-- @UUID.toText@ needs to be tweaked a little.
createID :: SP m => m ID
createID = ID . fixMSAD . UUID.toText <$> createUUID
  where
    fixMSAD :: ST -> ST
    fixMSAD = cs . ("id" <>) . filter (/= '-') . cs

createAuthnRequest :: SP m => Issuer -> m AuthnRequest
createAuthnRequest issuer = do
  x0 <- createID
  x1 <- (^. cfgVersion) <$> getConfig
  x2 <- getNow

  pure AuthnRequest
    { _rqID               = x0 :: ID
    , _rqVersion          = x1 :: Version
    , _rqIssueInstant     = x2 :: Time
    , _rqIssuer           = issuer
    }

redirect :: MonadError ServantErr m => URI -> [Header] -> m void
redirect uri extra = throwError err302 { errHeaders = ("Location", cs $ renderURI uri) : extra }

reject :: MonadError ServantErr m => LBS -> m void
reject msg = throwError err403 { errBody = msg }


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

instance (HasConfig m) => HasConfig (JudgeT m) where
  getConfig = JudgeT . lift . lift $ getConfig

instance SP m => SP (JudgeT m) where
  logger level = JudgeT . lift . lift . logger level
  createUUID = JudgeT . lift . lift $ createUUID
  getNow     = JudgeT . lift . lift $ getNow


judge :: (SP m) => AuthnResponse -> m AccessVerdict
judge resp = runJudgeT (judge' resp)

judge' :: (HasCallStack, MonadJudge m, SP m) => AuthnResponse -> m AccessVerdict
judge' resp = do
  -- if any assertion has any violated conditions, you get 'AccessDenied'.
  judgeConditions `mapM_` catMaybes ((^. assConditions) <$> resp ^. rspPayload)

  -- status must be success.
  case resp ^. rspStatus of
    StatusSuccess -> pure ()
    bad -> deny ["status: " <> cs (show bad)]

  -- issuer must be present and unique in assertions
  issuer <- case nub $ (^. assIssuer) <$> resp ^. rspPayload of
    [i] -> pure i
    [] -> giveup ["no statement issuer"]
    bad@(_:_:_) -> giveup ["multiple statement issuers not supported", cs $ show bad]

  case resp ^. rspPayload of
    [ass] -> case ass ^. assContents of
      SubjectAndStatements (Subject subject subjconds) (toList -> stmts) -> do
        checkAuthnStatement stmts
        checkSubjectConditions subjconds
        pure . AccessGranted $ UserId issuer subject
    []                           -> giveup ["no assertions"]
    _:_:_                        -> giveup ["not supported: more than one assertion"]

  -- TODO: 'judge' must only accept 'AuthResponse' values wrapped in 'SignaturesVerified', which can
  -- only be constructed by "Text.XML.DSig".

  -- TODO: implement 'checkSubjectConditions'!

  -- TODO: check requirements in [3/4.1.4.2]!
  -- (resp ^. rspInRespTo, if Just, must match request ID.  and other rules.)

  -- TODO: in case of error, log response (would xml be better?) and SP context for extraction of
  -- failing test cases in case of prod failures.

  -- also double-check against https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference

checkAuthnStatement :: MonadJudge m => [Statement] -> m ()
checkAuthnStatement = mapM_ go
  where
    go (AuthnStatement _ _ Nothing Nothing) = pure ()
    go (bad@AuthnStatement{})               = giveup ["bad AuthnStatement: " <> cs (show bad)]
    go _                                    = pure ()


checkSubjectConditions :: MonadJudge m => [SubjectConfirmation] -> m ()
checkSubjectConditions _ = pure ()


getAttributeStatements :: [Statement] -> [Attribute]
getAttributeStatements = mconcat . fmap go
  where
    go (AttributeStatement as) = toList as
    go _                       = []


requireAttributeText :: MonadJudge m => ST -> [Attribute] -> m ST
requireAttributeText key as = case filter ((== key) . (^. stattrName)) as of
  [(^. stattrValues) -> [val]] -> case val of AttributeValueUntyped txt -> pure txt
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

getIdPConfig :: SPNT m => ST -> m IdPConfig
getIdPConfig idpname = maybe crash pure . Map.lookup idpname . mkmap . (^. cfgIdps) =<< getConfig
  where
    crash = throwError err404 { errBody = "unknown IdP: " <> cs (show idpname) }
    mkmap = Map.fromList . fmap (\icfg -> (icfg ^. idpPath, icfg))
