{-# LANGUAGE OverloadedStrings #-}

-- | Partial implementation of <https://www.w3.org/TR/xmldsig-core/>.  We use hsaml2, hxt, x509 and
-- other dubious packages internally, but expose xml-types and cryptonite.
module Text.XML.DSig
  ( SignCreds(..), SignDigest(..), SignKey(..), SignPrivCreds(..), SignPrivKey(..)
  , parseKeyInfo, renderKeyInfo, keyInfoToCreds, keyInfoToPublicKey, mkSignCreds
  , verify, verifyRoot, verifyIO
  , signRoot
  )
where

import Control.Exception (throwIO, try, ErrorCall(ErrorCall), SomeException)
import Control.Monad.Except
import Data.EitherR (fmapL)
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
import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified SAML2.XML as HS hiding (URI, Node)
import qualified SAML2.XML.Canonical as HS
import qualified SAML2.XML.Signature as HS
import qualified Text.XML.HXT.DOM.XmlNode as HXT


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

-- | Read the KeyInfo element of a meta file's IDPSSODescriptor into a public key that can be used
-- for signing.  Tested for KeyInfo elements that contain an x509 certificate with a self-signed
-- signing RSA key.
--
-- TODO: verify self-signature?
parseKeyInfo :: (HasCallStack, MonadError String m) => LT -> m X509.SignedCertificate
parseKeyInfo (cs @LT @LBS -> lbs) = case HS.xmlToSAML @HS.KeyInfo =<< stripWhitespaceLBS lbs of
  Right keyinf -> case HS.keyInfoElements keyinf of
    HS.X509Data (HS.X509Certificate cert :| []) :| []
      -> pure cert
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

keyInfoToCreds :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m SignCreds
keyInfoToCreds cert = do
  digest <- case X509.signedAlg $ X509.getSigned cert of
    X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA -> pure SignDigestSha256
    bad -> throwError $ "unsupported: " <> show bad
  key <- case X509.certPubKey . X509.signedObject $ X509.getSigned cert of
    X509.PubKeyRSA pk -> pure $ SignKeyRSA pk
    bad -> throwError $ "unsupported: " <> show bad
  pure $ SignCreds digest key

keyInfoToPublicKey :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m RSA.PublicKey
keyInfoToPublicKey cert = keyInfoToCreds cert <&> \(SignCreds _ (SignKeyRSA key)) -> key

publicKeyToKeyInfo :: (HasCallStack) => RSA.PublicKey -> X509.SignedCertificate
publicKeyToKeyInfo = undefined


{- this fails, but i don't know why.  it this base64 encoding after all?

q :: [Either ASN1Error [ASN1]]
q = [decodeASN1 DER, decodeASN1 BER] <*> [q1]
  where
    q1 = "MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk"

-}

mkSignCreds :: (Crypto.MonadRandom m) => Int -> m (SignPrivCreds, SignCreds)
mkSignCreds size = do
  let rsaexp = 17
  (pubkey, privkey) <- RSA.generate size rsaexp
  pure ( SignPrivCreds SignDigestSha256 . SignPrivKeyRSA $ RSA.KeyPair privkey
       , SignCreds     SignDigestSha256 . SignKeyRSA     $ pubkey
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

    let _cert = publicKeyToKeyInfo $ RSA.toPublicKey keypair
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
