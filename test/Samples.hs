{-# LANGUAGE OverloadedStrings #-}

-- | haskell representations of the sample data in /test/xml/.
--
-- NOTE: be reluctant to update anything in this module.  always prefer to add new definitions.
-- different parts of the test suite depend on this in different ways, and you may need to update
-- those depending tests as well.
module Samples where

import Crypto.PubKey.RSA as RSA
import Data.List.NonEmpty (NonEmpty((:|)))
import SAML2.WebSSO
import URI.ByteString.QQ


-- source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference
microsoft_authnrequest_1 :: AuthnRequest
microsoft_authnrequest_1 = AuthnRequest {_rqID = ID {renderID = "id6c1c178c166d486687be4aaf5e482730"}, _rqIssueInstant = unsafeReadTime "2013-03-18T03:28:54.1839884Z", _rqIssuer = Issuer [uri|https://www.contoso.com|], _rqNameIDPolicy = Nothing}

microsoft_authnresponse_1 :: AuthnResponse
microsoft_authnresponse_1 = Response {_rspID = ID {renderID = "_ae75bd6c-6c76-4dc4-ae42-29153d6ca142"}, _rspInRespTo = Just ID {renderID = "id05873dd012c44e6db0bd59f5aa2e6a0a"}, _rspIssueInstant = unsafeReadTime "2018-04-13T06:33:02.772Z", _rspDestination = Just [uri|https://zb2.zerobuzz.net:60443/|], _rspIssuer = Just $ Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _rspStatus = StatusSuccess, _rspPayload = Assertion {_assID = ID {renderID = "_e9ae1025-bc03-4b5a-943c-c9fcb8730b21"}, _assIssueInstant = unsafeReadTime "2018-04-13T06:33:02.743Z", _assIssuer = Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _assConditions = Just Conditions {_condNotBefore = Just $ unsafeReadTime "2018-04-13T06:28:02.743Z", _condNotOnOrAfter = Just $ unsafeReadTime "2018-04-13T07:28:02.743Z", _condOneTimeUse = False, _condAudienceRestriction = Nothing}, _assContents = SubjectAndStatements Subject {_subjectID = opaqueNameID "E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84", _subjectConfirmations = [SubjectConfirmation {_scMethod = SubjectConfirmationMethodBearer, _scData = Just (SubjectConfirmationData {_scdNotBefore = Nothing, _scdNotOnOrAfter = unsafeReadTime "2018-04-13T06:38:02.743Z", _scdRecipient = [uri|https://zb2.zerobuzz.net:60443/|], _scdInResponseTo = Just ID {renderID = "id05873dd012c44e6db0bd59f5aa2e6a0a"}, _scdAddress = Nothing})}]} (AuthnStatement {_astAuthnInstant = unsafeReadTime "2018-03-27T06:23:57.851Z", _astSessionIndex = Just "_e9ae1025-bc03-4b5a-943c-c9fcb8730b21", _astSessionNotOnOrAfter = Nothing, _astSubjectLocality = Nothing} :| [])} :| []}

microsoft_authnresponse_2 :: AuthnResponse
microsoft_authnresponse_2 = Response {_rspID = ID {renderID = "_3aeb3054-e85f-41fa-a20f-0f278b327f4e"}, _rspInRespTo = Just ID {renderID = "idcf2299ac551b42f1aa9b88804ed308c2"}, _rspIssueInstant = unsafeReadTime "2018-04-14T09:58:58.457Z", _rspDestination = Just $ [uri|https://zb2.zerobuzz.net:60443/authresp|], _rspIssuer = Just $ Issuer [uri|http://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _rspStatus = StatusSuccess, _rspPayload = Assertion {_assID = ID {renderID = "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6"}, _assIssueInstant = unsafeReadTime "2018-04-14T09:58:58.442Z", _assIssuer = Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _assConditions = Just Conditions {_condNotBefore = Just (unsafeReadTime "2018-04-14T09:53:58.442Z"), _condNotOnOrAfter = Just (unsafeReadTime "2018-04-14T10:53:58.442Z"), _condOneTimeUse = False, _condAudienceRestriction = Nothing}, _assContents = SubjectAndStatements (Subject {_subjectID = opaqueNameID "xJxdqS8W2UXawbZZqpGFXKG4uEmO5GjijKD2RkMipBo", _subjectConfirmations = [SubjectConfirmation {_scMethod = SubjectConfirmationMethodBearer, _scData = Just (SubjectConfirmationData {_scdNotBefore = Nothing, _scdNotOnOrAfter = unsafeReadTime "2018-04-14T10:03:58.442Z", _scdRecipient = [uri|https://zb2.zerobuzz.net:60443/authresp|], _scdInResponseTo = Just ID {renderID = "idcf2299ac551b42f1aa9b88804ed308c2"}, _scdAddress = Nothing})}]}) (AuthnStatement {_astAuthnInstant = unsafeReadTime "2018-04-14T09:58:55.613Z", _astSessionIndex = Just "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6", _astSessionNotOnOrAfter = Nothing, _astSubjectLocality = Nothing} :| [])} :| []}

microsoft_idp_keyinfo :: RSA.PublicKey
microsoft_idp_keyinfo = RSA.PublicKey {RSA.public_size = 256, RSA.public_n = 25266449847616032605280887180445946447207827183577848474184616846136744459013940059297388901949168945284876940449831022307515873851064478442088422354857937225651881330471758496854838771727042040743247357142715828206862944363464254559789249948813601166263148331870847174783313061359856986236119735646527697584352746595070831856826144035963401689203402892945174546914103842786133972997748592644348449313622309013132898328267351769300154913558618070904948090075390540412224001257219178211139174816497946208851160331679253663348572295658494523941468674192526945936020222447823781738913444250167710107767554511823728989391, RSA.public_e = 65537}

onelogin_request_1 :: AuthnRequest
onelogin_request_1 = AuthnRequest
  { _rqID = ID "pfx41d8ef22-e612-8c50-9960-1b16f15741b3"
  , _rqIssueInstant = unsafeReadTime "2014-07-16T23:52:45Z"
  , _rqIssuer = Issuer [uri|http://sp.example.com/demo1/metadata.php|]
  , _rqNameIDPolicy = Nothing
  }
