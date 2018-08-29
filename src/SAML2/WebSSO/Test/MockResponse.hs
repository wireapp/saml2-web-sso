{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module SAML2.WebSSO.Test.MockResponse where

import Data.Generics.Uniplate.Data
import Data.String.Conversions
import Data.Time (getCurrentTime)
import Data.UUID as UUID
import Data.UUID.V4 as UUID
import GHC.Stack
import Lens.Micro
import SAML2.WebSSO
import Text.Hamlet.XML (xml)
import Text.XML
import Text.XML.DSig
import Text.XML.Util


newtype SignedAuthnResponse = SignedAuthnResponse { fromSignedAuthnResponse :: Document }
  deriving (Eq, Show)

mkAuthnResponse
  :: HasCallStack
  => SignPrivCreds -> IdPConfig extra -> AuthnRequest -> Bool -> IO SignedAuthnResponse
mkAuthnResponse = mkAuthnResponseWithModif id id

mkAuthnResponseWithSubj
  :: HasCallStack
  => NameID
  -> SignPrivCreds -> IdPConfig extra -> AuthnRequest -> Bool -> IO SignedAuthnResponse
mkAuthnResponseWithSubj subj = mkAuthnResponseWithModif modif id
  where
    modif = transformBis
      [ [ transformer $ \case
            (Element nm@"Subject" attrs nodes) -> Element nm attrs (render subj <> nodes)
            other -> other
        ]
      ]

mkAuthnResponseWithModif
  :: HasCallStack
  => ([Node] -> [Node]) -> ([Node] -> [Node])
  -> SignPrivCreds -> IdPConfig extra -> AuthnRequest -> Bool -> IO SignedAuthnResponse
mkAuthnResponseWithModif modifUnsignedAssertion modifAll creds idp authnreq grantAccess = do
  let freshNCName = ("_" <>) . UUID.toText <$> UUID.nextRandom
  assertionUuid <- freshNCName
  respUuid      <- freshNCName
  now           <- Time <$> getCurrentTime

  let issueInstant    = renderTime now
      expires         = renderTime $ 3600 `addTime` now
      issuer    :: ST = idp ^. idpIssuer . fromIssuer . to renderURI
      recipient :: ST = authnreq ^. rqIssuer . fromIssuer . to renderURI
      destination     = recipient
      inResponseTo    = renderID $ authnreq ^. rqID
      status
        | grantAccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
        | otherwise   = "urn:oasis:names:tc:SAML:2.0:status:Requester"

  assertion :: [Node]
    <- signElementIOAt 1 creds $ modifUnsignedAssertion
      [xml|
        <Assertion
          xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
          Version="2.0"
          ID="#{assertionUuid}"
          IssueInstant="#{issueInstant}">
            <Issuer>
                #{issuer}
            <Subject>
                <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                    #{"emil@email.com"}
                <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <SubjectConfirmationData
                      InResponseTo="#{inResponseTo}"
                      NotOnOrAfter="#{expires}"
                      Recipient="#{recipient}">
            <Conditions NotBefore="#{issueInstant}" NotOnOrAfter="#{expires}">
                <AudienceRestriction>
                    <Audience>
                        #{recipient}
            <AuthnStatement AuthnInstant="#{issueInstant}" SessionIndex="_e9ae1025-bc03-4b5a-943c-c9fcb8730b21">
                <AuthnContext>
                    <AuthnContextClassRef>
                        urn:oasis:names:tc:SAML:2.0:ac:classes:Password
      |]

  let authnResponse :: Element
      [NodeElement authnResponse] = modifAll
        [xml|
          <samlp:Response
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="#{respUuid}"
            Version="2.0"
            Destination="#{destination}"
            InResponseTo="#{inResponseTo}"
            IssueInstant="#{issueInstant}">
              <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
                  #{issuer}
              <samlp:Status>
                  <samlp:StatusCode Value="#{status}">
              ^{assertion}
        |]

  pure . SignedAuthnResponse $ mkDocument authnResponse
