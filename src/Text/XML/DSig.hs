-- | Partial implementation of <https://www.w3.org/TR/xmldsig-core/>.  We use hsaml2, hxt, x509 and
-- other dubious packages internally, but expose xml-types and cryptonite.
module Text.XML.DSig
  ( SignCreds(..), SignDigest(..), SignKey(..)
  , parseKeyInfo, renderKeyInfo, keyInfoToCreds

  , verify, verifyIO, Verified, fmapVerified, unverify
  )
where

import Control.Exception (SomeException, try)
import Control.Monad.Except
import Data.List.NonEmpty
import Data.Monoid ((<>))
import Data.String.Conversions
import GHC.Stack
import System.IO.Unsafe (unsafePerformIO)
import Text.XML
import Text.XML.Util

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Map as Map
import qualified Data.X509 as X509
import qualified SAML2.XML as HS hiding (URI, Node)
import qualified SAML2.XML.Signature as HS
import qualified Text.XML.HXT.Core as HXT


----------------------------------------------------------------------
-- metadata

-- | Read the KeyInfo element of a meta file's IDPSSODescriptor into a public key that can be used
-- for signing.  Tested for KeyInfo elements that contain an x509 certificate with a self-signed
-- signing RSA key.
--
-- TODO: verify self-signature?
parseKeyInfo :: (HasCallStack, MonadError String m) => LT -> m X509.SignedCertificate
parseKeyInfo lt = case HS.xmlToSAML @HS.KeyInfo $ cs lt of
  (Right (HS.keyInfoElements -> HS.X509Data (HS.X509Certificate cert :| []) :| [])) -> pure cert
  bad -> throwError $ "unsupported: " <> show bad

renderKeyInfo :: (HasCallStack) => X509.SignedCertificate -> LT
renderKeyInfo cert = cs . HS.samlToXML . HS.KeyInfo Nothing $ HS.X509Data (HS.X509Certificate cert :| []) :| []

data SignCreds = SignCreds SignDigest SignKey
  deriving (Eq, Show)

data SignDigest = SignDigestSha256
  deriving (Eq, Show, Bounded, Enum)

data SignKey = SignKeyRSA RSA.PublicKey
  deriving (Eq, Show)

keyInfoToCreds :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m SignCreds
keyInfoToCreds cert = do
  digest <- case X509.signedAlg $ X509.getSigned cert of
    X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA -> pure SignDigestSha256
    bad -> throwError $ "unsupported: " <> show bad
  key <- case X509.certPubKey . X509.signedObject $ X509.getSigned cert of
    X509.PubKeyRSA pk -> pure $ SignKeyRSA pk
    bad -> throwError $ "unsupported: " <> show bad
  pure $ SignCreds digest key


{- TODO: this fails, but i don't know why.  it this base64 encoding after all?

q :: [Either ASN1Error [ASN1]]
q = [decodeASN1 DER, decodeASN1 BER] <*> [q1]
  where
    q1 = "MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk"

-}


----------------------------------------------------------------------
-- signature verification

-- | [1/5]
--
-- DEPRECATED: Verified "use 'simpleVerifyAuthnResponse' instead (less type safety, but more flexible and understandable)."
newtype Verified a = Verified { unverify :: a }
  deriving (Eq, Show)

verify :: forall m. (MonadError String m)
       => RSA.PublicKey -> Element -> m (Verified Element)
verify key el = either (throwError . show @SomeException) pure . unsafePerformIO . try $ verifyIO key el

-- | Assumptions: the signedReference points to the root element; the signature is part of the
-- signed tree (enveloped signature).
verifyIO :: forall m. (m ~ IO {- FUTUREWORK: allow this to be any MonadThrow instance -})
       => RSA.PublicKey -> Element -> m (Verified Element)
verifyIO key el = do
  el' <- maybe (err "no parse") pure mkel'
  sid <- maybe (err "no signed-ID") pure mkSid
  try (HS.verifySignature key' sid el') >>= \case
    Left (e :: SomeException) -> err $ show e
    Right Nothing             -> err "no matching key/alg pair."
    Right (Just False)        -> err "invalid signature."
    Right (Just True)         -> pure $ Verified el
  where
    key' :: HS.PublicKeys
    key' = HS.PublicKeys Nothing . Just $ key

    mkel' :: Maybe HXT.XmlTree
    mkel' = HS.xmlToDoc . renderLBS def . mkDocument $ el

    mkSid :: Maybe String
    mkSid = cs <$> Map.lookup "ID" (elementAttributes el)

    err :: String -> m a
    err = fail . ("signature verification failed: " <>)

-- | This fake 'Functor' instance leaks the integrity of the contents, but we need this because we
-- want to first check the signature, then parse the application data.  Use with care!
fmapVerified :: (a -> b) -> Verified a -> Verified b
fmapVerified f (Verified a) = Verified $ f a



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
