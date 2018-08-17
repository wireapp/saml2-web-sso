{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

-- | Partial implementation of <https://www.w3.org/TR/xmldsig-core/>.  We use hsaml2, hxt, x509 and
-- other dubious packages internally, but expose xml-types and cryptonite.
module Text.XML.DSig
  ( SignCreds(..), SignDigest(..), SignKey(..), SignPrivCreds(..), SignPrivKey(..)
  , parseKeyInfo, renderKeyInfo, certToCreds, certToPublicKey
  , verifySelfSignature, mkSignCreds, mkSignCredsWithCert
  , verify, verifyRoot, verifyIO
  , signRoot
  , MonadSign(MonadSign), runMonadSign, signElementIO
  )
where

import Control.Exception (throwIO, try, ErrorCall(ErrorCall), SomeException)
import Control.Monad.Except
import Data.EitherR (fmapL)
import Data.Functor (($>))
import Data.List (foldl')
import Data.List.NonEmpty
import Data.Monoid ((<>))
import Data.String.Conversions
import Data.UUID as UUID
import GHC.Stack
import Lens.Micro ((<&>))
import Network.URI (URI, parseRelativeReference)
import System.IO.Unsafe (unsafePerformIO)
import System.Random (random, mkStdGen)
import Text.XML as XML
import Text.XML.Util

import qualified Crypto.Hash as Crypto
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.Random.Types as Crypto
import qualified Data.ByteArray as ByteArray
import qualified Data.Hourglass as Hourglass
import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified SAML2.XML as HS hiding (URI, Node)
import qualified SAML2.XML.Canonical as HS
import qualified SAML2.XML.Signature as HS
import qualified Text.XML.HXT.DOM.XmlNode as HXT
import qualified Time.System as Hourglass


data SignCreds = SignCreds SignDigest SignKey
  deriving (Eq, Show)

data SignDigest = SignDigestSha256
  deriving (Eq, Show, Bounded, Enum)

data SignKey = SignKeyRSA RSA.PublicKey
  deriving (Eq, Show)

data SignPrivCreds = SignPrivCreds SignDigest SignPrivKey
  deriving (Eq, Show)

data SignPrivKey = SignPrivKeyRSA RSA.KeyPair
  deriving (Eq, Show)


----------------------------------------------------------------------
-- public keys and certificats

verifySelfSignature :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m ()
verifySelfSignature cert = do
  certToCreds cert >>= \case
    SignCreds SignDigestSha256 (SignKeyRSA pubkey) -> do
      let signedMessage  = X509.getSignedData cert
          signatureValue = X509.signedSignature $ X509.getSigned cert
      unless (RSA.verify (Just Crypto.SHA256) pubkey signedMessage signatureValue) $
        throwError "verifySelfSignature: invalid signature."

-- | Read the KeyInfo element of a meta file's IDPSSODescriptor into a public key that can be used
-- for signing.  Tested for KeyInfo elements that contain an x509 certificate with a self-signed
-- signing RSA key.
parseKeyInfo :: (HasCallStack, MonadError String m) => LT -> m X509.SignedCertificate
parseKeyInfo (cs @LT @LBS -> lbs) = case HS.xmlToSAML @HS.KeyInfo =<< stripWhitespaceLBS lbs of
  Right keyinf -> case HS.keyInfoElements keyinf of
    HS.X509Data (HS.X509Certificate cert :| []) :| []
      -> verifySelfSignature cert $> cert
    HS.X509Data (HS.X509Certificate _ :| bad) :| bad'
      -> throwError $ "unreadable trailing data or noise: " <> show (bad, bad')
    unsupported
      -> throwError $ "expected exactly one KeyInfo element: " <> show unsupported
  Left errmsg
    -> throwError $ "expected exactly one KeyInfo XML element: " <> errmsg

-- | Call 'stripWhitespaceDoc' on a rendered bytestring.
stripWhitespaceLBS :: m ~ Either String => LBS -> m LBS
stripWhitespaceLBS lbs = renderLBS def . stripWhitespace <$> fmapL show (parseLBS def lbs)

renderKeyInfo :: (HasCallStack) => X509.SignedCertificate -> LT
renderKeyInfo cert = cs . HS.samlToXML . HS.KeyInfo Nothing $ HS.X509Data (HS.X509Certificate cert :| []) :| []

certToCreds :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m SignCreds
certToCreds cert = do
  digest <- case X509.signedAlg $ X509.getSigned cert of
    X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA -> pure SignDigestSha256
    bad -> throwError $ "unsupported: " <> show bad
  key <- case X509.certPubKey . X509.signedObject $ X509.getSigned cert of
    X509.PubKeyRSA pk -> pure $ SignKeyRSA pk
    bad -> throwError $ "unsupported: " <> show bad
  pure $ SignCreds digest key

certToPublicKey :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m RSA.PublicKey
certToPublicKey cert = certToCreds cert <&> \(SignCreds _ (SignKeyRSA key)) -> key

publicKeyToCert :: (HasCallStack) => RSA.PublicKey -> X509.SignedCertificate
publicKeyToCert = undefined


mkSignCreds :: (Crypto.MonadRandom m, MonadIO m) => Int -> m (SignPrivCreds, SignCreds)
mkSignCreds size = mkSignCredsWithCert Nothing size <&> \(priv, pub, _) -> (priv, pub)

-- | If first argument @validSince@ is @Nothing@, use cucrent system time.
mkSignCredsWithCert :: forall m. (Crypto.MonadRandom m, MonadIO m)
                    => Maybe Hourglass.DateTime -> Int -> m (SignPrivCreds, SignCreds, X509.SignedCertificate)
mkSignCredsWithCert mValidSince size = do
  let rsaexp = 17
  (pubkey, privkey) <- RSA.generate size rsaexp

  validSince :: Hourglass.DateTime <- maybe (liftIO Hourglass.dateCurrent) pure mValidSince
  let validUntil = validSince `Hourglass.timeAdd` mempty { Hourglass.durationHours = 24 * 365 * 20 }

      signcert :: SBS -> m (SBS, X509.SignatureALG)
      signcert sbs = (, sigalg) <$> sigval
        where
          sigalg = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA
          sigval :: m SBS = liftIO $
            RSA.signSafer (Just Crypto.SHA256) privkey sbs
              >>= either (throwIO . ErrorCall . show) pure

  cert <- X509.objectToSignedExactF signcert X509.Certificate
        { X509.certVersion = 2 :: Int
        , X509.certSerial = 387928798798718181888591698169861 :: Integer
        , X509.certSignatureAlg = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA
        , X509.certIssuerDN = X509.DistinguishedName []
        , X509.certValidity = (validSince, validUntil)
        , X509.certSubjectDN = X509.DistinguishedName []
        , X509.certPubKey = X509.PubKeyRSA pubkey
        , X509.certExtensions = X509.Extensions Nothing
        }

  pure ( SignPrivCreds SignDigestSha256 . SignPrivKeyRSA $ RSA.KeyPair privkey
       , SignCreds     SignDigestSha256 . SignKeyRSA     $ pubkey
       , cert
       )


----------------------------------------------------------------------
-- signature verification

verify :: forall m. (MonadError String m) => SignCreds -> LBS -> String -> m ()
verify creds el signedID = either (throwError . show) pure . unsafePerformIO
                         $ verifyIO creds el signedID

verifyRoot :: forall m. (MonadError String m) => SignCreds -> LBS -> m ()
verifyRoot creds el = do
  signedID <- do
    XML.Document _ (XML.Element _ attrs _) _
      <- either (throwError . ("Could not parse signed document: " <>) . cs . show)
                pure
                (XML.parseLBS XML.def el)
    maybe (throwError $ "Could not parse signed document: no ID attribute in root element." <> show el)
          (pure . cs)
          (Map.lookup "ID" attrs)
  verify creds el signedID

verifyIO :: SignCreds -> LBS -> String -> IO (Either HS.SignatureError ())
verifyIO (SignCreds SignDigestSha256 (SignKeyRSA key)) el signedID = do
  el' <- either (throwIO . ErrorCall) pure $ HS.xmlToDocE el
  HS.verifySignature (HS.PublicKeys Nothing . Just $ key) signedID el'


----------------------------------------------------------------------
-- signature creation

-- | Make sure that root node node has ID attribute and sign it.  This is similar to the more
-- primitive 'HS.generateSignature'.
signRoot :: (Crypto.MonadRandom m, MonadError String m) => SignPrivCreds -> XML.Document -> m XML.Document
signRoot (SignPrivCreds hashAlg (SignPrivKeyRSA keypair)) doc
  = do
    (docWithID :: XML.Document, reference) <- addRootIDIfMissing doc
    docInHXT <- conduitToHxt docWithID

    let canoAlg = HS.CanonicalXMLExcl10 True
        transforms = Just . HS.Transforms $
                       HS.Transform { HS.transformAlgorithm = HS.Identified HS.TransformEnvelopedSignature
                                    , HS.transformInclusiveNamespaces = Nothing
                                    , HS.transform = []
                                    }
                  :| [ HS.Transform { HS.transformAlgorithm = HS.Identified (HS.TransformCanonicalization canoAlg)
                                    , HS.transformInclusiveNamespaces = Nothing
                                    , HS.transform = []
                                    }
                     ]

    docCanonic :: SBS
           <- either (throwError . show @SomeException) (pure . cs) . unsafePerformIO . try $
              HS.applyTransforms transforms (HXT.mkRoot [] [docInHXT])

    let digest :: SBS
        digest = case hashAlg of
          SignDigestSha256 -> ByteArray.convert $ Crypto.hash @SBS @Crypto.SHA256 docCanonic

    let signedInfo = HS.SignedInfo
          { signedInfoId = Nothing :: Maybe HS.ID
          , signedInfoCanonicalizationMethod = HS.CanonicalizationMethod (HS.Identified canoAlg) Nothing []
          , signedInfoSignatureMethod = HS.SignatureMethod (HS.Identified HS.SignatureRSA_SHA256) Nothing []
          , signedInfoReference = HS.Reference
            { referenceId = Nothing
            , referenceURI = Just reference
            , referenceType = Nothing
            , referenceTransforms = transforms
            , referenceDigestMethod = HS.DigestMethod (HS.Identified HS.DigestSHA256) []
            , referenceDigestValue = digest
            } :| []
          }
          -- (note that there are two rounds of SHA256 application, hence two mentions of the has alg here)

    signedInfoSBS :: SBS
      <- either (throwError . show @SomeException) (pure . cs) . unsafePerformIO . try $
           HS.applyCanonicalization (HS.signedInfoCanonicalizationMethod signedInfo) Nothing $
             HS.samlToDoc signedInfo

    sigval :: SBS
           <- either (throwError . show @RSA.Error) pure
              =<< RSA.signSafer (Just Crypto.SHA256)
                                (RSA.toPrivateKey keypair)
                                signedInfoSBS

    let _cert = publicKeyToCert $ RSA.toPublicKey keypair
        sig = HS.Signature
          { signatureId = Nothing :: Maybe HS.ID
          , signatureSignedInfo = signedInfo :: HS.SignedInfo
          , signatureSignatureValue = HS.SignatureValue Nothing sigval :: HS.SignatureValue
          , signatureKeyInfo = Nothing :: Maybe HS.KeyInfo  -- @Just _cert@ would be nice, but we'd have to implement that.
          , signatureObject = []
          }

    unless (RSA.verify (Just Crypto.SHA256) (RSA.toPublicKey keypair) signedInfoSBS sigval) $
      throwError "signRoot: internal error: failed to verify my own signature!"

    injectSignedInfoAtRoot sig =<< hxtToConduit docInHXT

addRootIDIfMissing :: forall m. (MonadError String m, Crypto.MonadRandom m) => XML.Document -> m (XML.Document, URI)
addRootIDIfMissing (XML.Document prol (Element tag attrs nodes) epil) = do
  (fresh, ref) <- maybe makeID keepID $ Map.lookup "ID" attrs
  uriref <- maybe (throwError "bad reference URI") pure . parseRelativeReference . cs $ "#" <> ref
  let updAttrs = if fresh then Map.insert "ID" ref else id
  pure (XML.Document prol (Element tag (updAttrs attrs) nodes) epil, uriref)
  where
    makeID :: m (Bool, ST)
    makeID = (True,) . UUID.toText <$> randomUUID

    keepID :: ST -> m (Bool, ST)
    keepID = pure . (False,)

randomUUID :: Crypto.MonadRandom m => m UUID.UUID
randomUUID = fst . random . mkStdGen . fromIntegral <$> randomInteger

-- | (uses 64 bits of entropy)
randomInteger :: Crypto.MonadRandom m => m Integer
randomInteger = Crypto.getRandomBytes 8
            <&> ByteArray.unpack @ByteArray.Bytes
            <&> fmap fromIntegral
            <&> foldl' (*) 1

injectSignedInfoAtRoot :: MonadError String m => HS.Signature -> XML.Document -> m XML.Document
injectSignedInfoAtRoot signedInfo (XML.Document prol (Element tag attrs nodes) epil) = do
  XML.Document _ signedInfoXML _ <- samlToConduit signedInfo
  pure $ XML.Document prol (Element tag attrs (XML.NodeElement signedInfoXML : nodes)) epil



{-

-- other implementations for testing:

https://www.aleksey.com/xmlsec/ (C)
https://github.com/yaronn/xml-crypto (js)


-- some data types from the xml:dsig standard

data XMLDSig = XMLDSig
  { _xmlsigReference              :: XMLNodeID
  , _xmlsigCanonicalizationMethod :: CanonicalizationMethod
  , _xmlsigDigestMethod           :: DigestMethod
  , _xmlsigSignatureMethod        :: SignatureMethod
  , _xmlsigTransforms             :: [Transform]
  , _xmlsigDigestValue            :: DigestValue
  , _xmlsigSignatureValue         :: SignatureValue
  , _xmlsigKeyInfo                :: SignerIdentity
  }
  deriving (Eq, Show)

newtype XMLNodeID = XMLNodeID ST
  deriving (Eq, Show)

data CanonicalizationMethod = ExcC14N
  deriving (Eq, Show, Bounded, Enum)

data SignatureMethod = SignatureRsaSha1
  deriving (Eq, Show, Bounded, Enum)

data DigestMethod = DigestSha1
  deriving (Eq, Show, Bounded, Enum)

data Transform =
    TransformExcC14N
  | TransformEnvelopedSignature
  deriving (Eq, Show, Bounded, Enum)

newtype DigestValue = DigestValue ST
  deriving (Eq, Show)

newtype SignatureValue = SignatureValue ST
  deriving (Eq, Show)

newtype SignerIdentity = X509Certificate ST
  deriving (Eq, Show)

-}


----------------------------------------------------------------------
-- testing

newtype MonadSign a = MonadSign { runMonadSign' :: ExceptT String IO a }
  deriving (Functor, Applicative, Monad)

runMonadSign :: MonadSign a -> IO (Either String a)
runMonadSign = runExceptT . runMonadSign'

instance Crypto.MonadRandom MonadSign where
  getRandomBytes l = MonadSign . ExceptT $ Right <$> Crypto.getRandomBytes l

instance MonadError String MonadSign where
  throwError = MonadSign . throwError
  catchError (MonadSign m) handler = MonadSign $ m `catchError` (runMonadSign' . handler)

signElementIO :: HasCallStack => SignPrivCreds -> [Node] -> IO [Node]
signElementIO creds [NodeElement el] = do
  let docToNodes :: Document -> [Node]
      docToNodes (Document _ el' _) = [NodeElement el']
  eNodes :: Either String [Node]
    <- runMonadSign . fmap docToNodes . signRoot creds . mkDocument $ el
  either error pure eNodes
signElementIO _ bad = error $ show bad
