{-# LANGUAGE OverloadedStrings #-}

-- | Partial implementation of <https://www.w3.org/TR/xmldsig-core/>.  We use hsaml2, hxt, x509 and
-- other dubious packages internally, but expose xml-types and cryptonite.
module Text.XML.DSig
  ( SignCreds(..), SignDigest(..), SignKey(..)
  , parseKeyInfo, renderKeyInfo, keyInfoToCreds, keyInfoToPublicKey

  , verify, verifyRoot, verifyIO
  )
where

import Control.Exception (throwIO, ErrorCall(ErrorCall))
import Control.Monad.Except
import Data.Char (isSpace)
import Data.EitherR (fmapL)
import Data.List.NonEmpty
import Data.Monoid ((<>))
import Data.String.Conversions
import GHC.Stack
import Lens.Micro ((<&>))
import System.IO.Unsafe (unsafePerformIO)
import Text.XML as XML

import qualified Data.Generics.Uniplate.Data as Uniplate
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Map as Map
import qualified Data.Text as ST
import qualified Data.X509 as X509
import qualified SAML2.XML as HS hiding (URI, Node)
import qualified SAML2.XML.Signature as HS


----------------------------------------------------------------------
-- metadata

-- | Read the KeyInfo element of a meta file's IDPSSODescriptor into a public key that can be used
-- for signing.  Tested for KeyInfo elements that contain an x509 certificate with a self-signed
-- signing RSA key.
--
-- TODO: verify self-signature?
parseKeyInfo :: (HasCallStack, MonadError String m) => LT -> m X509.SignedCertificate
parseKeyInfo (cs @LT @LBS -> lbs) = case HS.xmlToSAML @HS.KeyInfo =<< stripWhitespace lbs of
  Right keyinf -> case HS.keyInfoElements keyinf of
    HS.X509Data (HS.X509Certificate cert :| []) :| []
      -> pure cert
    HS.X509Data (HS.X509Certificate _ :| bad) :| bad'
      -> throwError $ "unreadable trailing data or noise: " <> show (bad, bad')
    unsupported
      -> throwError $ "expected exactly one KeyInfo element: " <> show unsupported
  Left errmsg
    -> throwError $ "expected exactly one KeyInfo XML element: " <> errmsg

-- | Remove all whitespace in the text nodes of the xml document.  This requires parsing and re-rendering.
stripWhitespace :: m ~ Either String => LBS -> m LBS
stripWhitespace lbs = renderLBS def . stripws <$> fmapL show (parseLBS def lbs)
  where
    stripws :: Document -> Document
    stripws = Uniplate.transformBis
      [ [Uniplate.transformer $ \case
            (NodeContent txt) -> NodeContent $ ST.filter (not . isSpace) txt
            other -> other
        ]
      , [Uniplate.transformer $ \case
            (Element nm attrs nodes) -> Element nm attrs (Prelude.filter (/= NodeContent "") $ nodes)
        ]
      ]

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

keyInfoToPublicKey :: (HasCallStack, MonadError String m) => X509.SignedCertificate -> m RSA.PublicKey
keyInfoToPublicKey cert = keyInfoToCreds cert <&> \(SignCreds _ (SignKeyRSA key)) -> key


{- this fails, but i don't know why.  it this base64 encoding after all?

q :: [Either ASN1Error [ASN1]]
q = [decodeASN1 DER, decodeASN1 BER] <*> [q1]
  where
    q1 = "MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk"

-}


----------------------------------------------------------------------
-- signature verification

verify :: forall m. (MonadError String m) => X509.SignedCertificate -> LBS -> String -> m ()
verify creds el signedID = either (throwError . show) pure . unsafePerformIO
                         $ verifyIO creds el signedID

verifyRoot :: forall m. (MonadError String m) => X509.SignedCertificate -> LBS -> m ()
verifyRoot creds el = do
  signedID <- do
    XML.Document _ (XML.Element _ attrs _) _
      <- either (throwError . ("Could not parse signed document: " <>) . cs . show)
                pure
                (XML.parseLBS XML.def el)
    maybe (throwError "Could not parse signed document: no ID attribute in root element.")
          (pure . cs)
          (Map.lookup "ID" attrs)
  verify creds el signedID

verifyIO :: X509.SignedCertificate -> LBS -> String -> IO (Either HS.SignatureError ())
verifyIO creds el signedID = do
  key :: RSA.PublicKey <- case keyInfoToCreds creds of
    Right (SignCreds SignDigestSha256 (SignKeyRSA k)) -> pure k
    Left msg -> throwIO . ErrorCall . show $ msg
  el' <- either (throwIO . ErrorCall) pure $ HS.xmlToDocE el
  HS.verifySignature (HS.PublicKeys Nothing . Just $ key) signedID el'




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
