{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}

module SAML2.WebSSO.SP where

import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Writer
import Data.Foldable (toList)
import Data.List
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe
import Data.String.Conversions
import Data.Time
import Data.UUID (UUID)
import GHC.Stack
import Lens.Micro
import Lens.Micro.TH
import SAML2.Util
import SAML2.WebSSO.Config
import SAML2.WebSSO.Types
import Servant.API hiding (URI(..))
import Servant hiding (URI(..))
import URI.ByteString

import qualified Data.Semigroup
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID


----------------------------------------------------------------------
-- class

-- | Application logic of the service provider.
class (HasConfig m, Monad m) => SP m where
  logger :: Level -> String -> m ()
  default logger :: MonadIO m => Level -> String -> m ()
  logger = loggerConfIO

  createUUID :: m UUID
  default createUUID :: MonadIO m => m UUID
  createUUID = createUUIDIO

  getNow :: m Time
  default getNow :: MonadIO m => m Time
  getNow = getNowIO

class (SP m) => SPStore m where
  -- Store 'AuthnRequest' for later check against the recipient in the 'AuthnResponse'.  Will be
  -- stored until 'Time', afterwards is considered garbage-collectible.
  storeRequest :: ID AuthnRequest -> Time -> m ()

  -- Do we know of an 'AuthnRequest' with that 'ID'?
  checkAgainstRequest :: ID AuthnRequest -> m Bool

  -- Store 'Assertion's to prevent replay attack.  'Time' argument is end of life (IDs may be
  -- garbage collected after that time).  Iff assertion has already been stored and is not dead yet,
  -- return 'False'.
  storeAssertion :: ID Assertion -> Time -> m Bool

class (MonadError err m) => SPStoreIdP err m where
  storeIdPConfig       :: IdPConfig (ConfigExtra m) -> m ()
  getIdPConfig         :: IdPId -> m (IdPConfig (ConfigExtra m))
  getIdPConfigByIssuer :: Issuer -> m (IdPConfig (ConfigExtra m))

-- | HTTP handling of the service provider.
class (SP m, SPStore m, SPStoreIdP err m, MonadError err m) => SPHandler err m where
  type NTCTX m :: *
  nt :: forall x. NTCTX m -> m x -> Handler x


----------------------------------------------------------------------
-- combinators

loggerConfIO :: (HasConfig m, MonadIO m) => Level -> String -> m ()
loggerConfIO level msg = do
  cfgsays <- (^. cfgLogLevel) <$> getConfig
  loggerIO cfgsays level msg

loggerIO :: MonadIO m => Level -> Level -> String -> m ()
loggerIO cfgsays level msg = if level >= cfgsays
  then liftIO $ putStrLn msg
  else pure ()

createUUIDIO :: MonadIO m => m UUID
createUUIDIO = liftIO UUID.nextRandom

getNowIO :: MonadIO m => m Time
getNowIO = Time <$> liftIO getCurrentTime

-- | (Microsoft Active Directory likes IDs to be of the form @id<32 hex digits>@: @ID . cs . ("id"
-- <>) . filter (/= '-') . cs . UUID.toText <$> createUUID@.  Hopefully the more common form
-- produced by this function is also ok.)
createID :: SP m => m (ID a)
createID = ID . ("_" <>) . UUID.toText <$> createUUID

-- | Generate an 'AuthnRequest' value for the initiate-login response.  The 'NameIdPolicy' is
-- 'NameIDFUnspecified'.  Do not use email here unless you are confident that there won't be issues
-- with changing email addresses that you don't know how to resolve.
createAuthnRequest :: (SP m, SPStore m) => NominalDiffTime -> m Issuer -> m AuthnRequest
createAuthnRequest lifeExpectancySecs getIssuer = do
  _rqID           <- createID
  _rqVersion      <- (^. cfgVersion) <$> getConfig
  _rqIssueInstant <- getNow
  _rqIssuer       <- getIssuer
  let _rqNameIDPolicy = Just $ NameIdPolicy NameIDFUnspecified Nothing True
  storeRequest _rqID (addTime lifeExpectancySecs _rqIssueInstant)
  pure AuthnRequest{..}


----------------------------------------------------------------------
-- paths

getSsoURI :: forall m endpoint api.
                  ( HasCallStack
                  , HasConfig m
                  , IsElem endpoint api
                  , HasLink endpoint
#if MIN_VERSION_servant(0,14,0)
                  , ToHttpApiData (MkLink endpoint Link)
#else
                  , ToHttpApiData (MkLink endpoint)
#endif
                  )
               => Proxy api -> Proxy endpoint -> m URI
getSsoURI proxyAPI proxyAPIAuthResp = extpath . (^. cfgSPSsoURI) <$> getConfig
  where
    extpath :: URI -> URI
    extpath = (=/ (cs . toUrlPiece $ safeLink proxyAPI proxyAPIAuthResp))

-- | 'getSsoURI' for links that have one variable path segment.
--
-- FUTUREWORK: this is only sometimes what we need.  it would be nice to have a type class with a
-- method 'getSsoURI' for arbitrary path arities.
getSsoURI' :: forall endpoint api a (f :: * -> *) t.
              ( HasConfig f
              , MkLink endpoint ~ (t -> a)
#if MIN_VERSION_servant(0,14,0)
              , HasLink endpoint Link
#else
              , HasLink endpoint
#endif
              , ToHttpApiData a
              , IsElem endpoint api
              ) => Proxy api -> Proxy endpoint -> t -> f URI
getSsoURI' proxyAPI proxyAPIAuthResp idpid = extpath . (^. cfgSPSsoURI) <$> getConfig
  where
    extpath :: URI -> URI
    extpath = (=/ (cs . toUrlPiece $ safeLink proxyAPI proxyAPIAuthResp idpid))


----------------------------------------------------------------------
-- compute access verdict(s)

-- | This monad collects errors in a writer, so that the reasons for access denial are as helpful as
-- possible.  It is a little like an exception monad, except you can throw several exceptions
-- without interrupting the flow, and will get a list of them at the end.
--
-- NOTE: @-XGeneralizedNewtypeDeriving@ does not help with the boilerplate instances below, since
-- this is a transformer stack and not a concrete 'Monad'.
newtype JudgeT m a = JudgeT
  { fromJudgeT :: ExceptT [String] (WriterT [String] (ReaderT JudgeCtx m)) a }

data JudgeCtx = JudgeCtx
  { _judgeCtxRequestIssuer :: Issuer
  , _judgeCtxResponseURI   :: URI
  }

makeLenses ''JudgeCtx

runJudgeT :: forall m. (Monad m, SP m) => JudgeCtx -> JudgeT m AccessVerdict -> m AccessVerdict
runJudgeT ctx (JudgeT em) = fmap collectErrors . (`runReaderT` ctx) . runWriterT $ runExceptT em
  where
    collectErrors :: (Either [String] AccessVerdict, [String]) -> AccessVerdict
    collectErrors (Left errs, errs')    = AccessDenied . fmap cs $ errs' <> errs
    collectErrors (Right _, errs@(_:_)) = AccessDenied . fmap cs $ errs
    collectErrors (Right v, [])         = v

-- the parts of the MonadError, MonadWriter interfaces we want here.
class (Functor m, Applicative m, Monad m) => MonadJudge m where
  getJudgeCtx :: m JudgeCtx
  deny :: [String] -> m ()
  giveup :: [String] -> m a

instance (Functor m, Applicative m, Monad m) => MonadJudge (JudgeT m) where
  getJudgeCtx = JudgeT . lift . lift $ ask
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
  type ConfigExtra (JudgeT m) = ConfigExtra m
  getConfig = JudgeT . lift . lift . lift $ getConfig

instance SP m => SP (JudgeT m) where
  logger level     = JudgeT . lift . lift . lift . logger level
  createUUID       = JudgeT . lift . lift . lift $ createUUID
  getNow           = JudgeT . lift . lift . lift $ getNow

instance SPStore m => SPStore (JudgeT m) where
  storeRequest r      = JudgeT . lift . lift . lift . storeRequest r
  checkAgainstRequest = JudgeT . lift . lift . lift . checkAgainstRequest
  storeAssertion i    = JudgeT . lift . lift . lift . storeAssertion i


-- | [3/4.1.4.2], [3/4.1.4.3]; specific to active-directory:
-- <https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference>
judge :: (SP m, SPStore m) => AuthnResponse -> JudgeCtx -> m AccessVerdict
judge resp ctx = runJudgeT ctx (judge' resp)

-- TODO: crash for any extensions of the xml tree that we don't understand!

judge' :: (HasCallStack, MonadJudge m, SP m, SPStore m) => AuthnResponse -> m AccessVerdict
judge' resp = do
  either (deny . (:[])) pure . statusIsSuccess $ resp ^. rspStatus

  checkInResponseTo `mapM_` (resp ^. rspInRespTo)
  checkNotInFuture "Issuer instant" $ resp ^. rspIssueInstant
  maybe (pure ()) (checkDestination "response destination") (resp ^. rspDestination)
  checkAssertions (resp ^. rspIssuer) (resp ^. rspPayload)

checkInResponseTo :: (SPStore m, MonadJudge m) => ID AuthnRequest -> m ()
checkInResponseTo req = do
  ok <- checkAgainstRequest req
  unless ok . deny $ ["invalid InResponseTo field: " <> show req]

checkNotInFuture :: (SP m, MonadJudge m) => String -> Time -> m ()
checkNotInFuture msg tim = do
  now <- getNow
  unless (tim < now) $
    deny [msg <> " in the future: " <> show tim]

-- | Check that the response is intended for us (based on config's finalize-login uri stored in
-- 'JudgeCtx').
checkDestination :: (HasConfig m, MonadJudge m) => String -> URI -> m ()
checkDestination msg (renderURI -> expectedByIdp) = do
  (renderURI -> expectedByUs) <- (^. judgeCtxResponseURI) <$> getJudgeCtx
  unless (expectedByUs == expectedByIdp) $ do
    deny [mconcat [ "bad ",  msg, ": "
                  , "expected by us: ", show expectedByUs, "; "
                  , "expected by IdP: any of " <> show expectedByIdp
                  ]
         ]

checkAssertions :: (SP m, SPStore m, MonadJudge m) => Maybe Issuer -> NonEmpty Assertion -> m AccessVerdict
checkAssertions missuer (toList -> assertions) = do
  forM_ assertions $ \ass -> do
    checkNotInFuture "Assertion IssueInstant" (ass ^. assIssueInstant)
    storeAssertion (ass ^. assID) (ass ^. assEndOfLife)
  judgeConditions `mapM_` catMaybes ((^. assConditions) <$> assertions)

  issuer <- case nub $ (^. assIssuer) <$> assertions of
    [i] -> pure i
    [] -> giveup ["no statement issuer"]
    bad@(_:_:_) -> giveup ["multiple statement issuers not supported", show bad]

  unless (maybe True (issuer ==) missuer) $
    deny ["issuers mismatch: " <> show (missuer, issuer)]

  subject
    <- do
         -- subject must occur at least once; there must not be two different subjects.  (this is probably a
         -- slight restriction of the excessively vague specs.)
         case nub $ (^. assContents . sasSubject) <$> assertions of
           [Subject s _] -> pure s
           []                -> giveup ["no subjects"]
           bad@(_:_:_)       -> giveup ["more than one subject: " <> show bad]

  checkSubjectConfirmations assertions

  let statements :: [Statement]
      statements = mconcat $ (^. assContents . sasStatements . to toList) <$> assertions

  when (null statements) $
    deny ["no statements in assertions"]

  when (null . catMaybes $ (^? _AuthnStatement) <$> statements) $
    deny ["no AuthnStatement in assertions"]

  checkStatement `mapM_` statements
  pure $ AccessGranted (UserRef issuer subject)

checkStatement :: (SP m, MonadJudge m) => Statement -> m ()
checkStatement = \case
  (AuthnStatement issued _ mtimeout _) -> do
    checkNotInFuture "AuthnStatement IssueInstance" issued
    forM_ mtimeout $ \timeout -> do
      now <- getNow
      when (timeout <= now) $ deny ["AuthnStatement expired at " <> show timeout]
  (AttributeStatement{}) -> pure ()

-- | Check all 'SubjectConfirmation's and 'Subject's in all 'Assertion'.  Deny if not at least one
-- confirmation has method "bearer".
checkSubjectConfirmations :: (SP m, SPStore m, MonadJudge m) => [Assertion] -> m ()
checkSubjectConfirmations assertions = do
  bearerFlags :: [[HasBearerConfirmation]] <- forM assertions $
    \assertion -> case assertion ^. assContents . sasSubject of
      Subject _ confs -> checkSubjectConfirmation assertion `mapM` confs

  unless (mconcat (mconcat bearerFlags) == HasBearerConfirmation) $
    deny ["no bearer-confirmed subject"]

  pure ()

data HasBearerConfirmation = HasBearerConfirmation | NoBearerConfirmation
  deriving (Eq, Ord, Bounded, Enum)

instance Monoid HasBearerConfirmation where
  mappend = (Data.Semigroup.<>)
  mempty = maxBound

instance Data.Semigroup.Semigroup HasBearerConfirmation where
  (<>) = min

-- | Locally check one 'SubjectConfirmation' and deny if there is a problem.  If this is a
-- confirmation of method "bearer", return 'HasBearerConfirmation'.
checkSubjectConfirmation :: (SPStore m, MonadJudge m) => Assertion -> SubjectConfirmation -> m HasBearerConfirmation
checkSubjectConfirmation ass conf = do
  let bearer = if (conf ^. scMethod) == SubjectConfirmationMethodBearer
        then HasBearerConfirmation
        else NoBearerConfirmation

  when (bearer == HasBearerConfirmation) $ do
    unless (any (isJust . (^. condAudienceRestriction)) (ass ^. assConditions)) $
      deny ["bearer-confirmed assertions must be audience-restricted."]
      -- (the actual validation of the field, given it is Just, happens in 'judgeConditions'.)

  checkSubjectConfirmationData bearer `mapM_` (conf ^. scData)

  pure bearer

checkSubjectConfirmationData :: (HasConfig m, SP m, SPStore m, MonadJudge m)
  => HasBearerConfirmation -> SubjectConfirmationData -> m ()
checkSubjectConfirmationData bearer confdat = do
  when (bearer == HasBearerConfirmation) $ do
    unless (isNothing $ confdat ^. scdNotBefore) $
      deny ["bearer confirmation must not have attribute."]

  checkDestination "confirmation recipient" $ confdat ^. scdRecipient

  getNow >>= \now -> when (now >= confdat ^. scdNotOnOrAfter) $
    deny ["SubjectConfirmation with invalid NotOnOrAfter: " <> show (confdat ^. scdNotOnOrAfter)]

  checkInResponseTo `mapM_` (confdat ^. scdInResponseTo)

judgeConditions :: (HasCallStack, MonadJudge m, SP m) => Conditions -> m ()
judgeConditions (Conditions lowlimit uplimit onetimeuse maudiences) = do
  now <- getNow
  when (maybe False (now <) lowlimit) $
    deny ["violation of NotBefore condition: "  <> show now <> " >= " <> show lowlimit]
  when (maybe False (now >=) uplimit) $
    deny ["violation of NotOnOrAfter condition" <> show now <> " < "  <> show uplimit]
  when onetimeuse $
    deny ["unsupported flag: OneTimeUse"]

  Issuer us <- (^. judgeCtxRequestIssuer) <$> getJudgeCtx
  case maudiences of
    Just aus | us `notElem` aus
      -> deny ["I am " <> cs (renderURI us) <> ", and I am not in the target audience [" <>
               intercalate ", " (cs . renderURI <$> toList aus) <> "] of this response."]
    _ -> pure ()
