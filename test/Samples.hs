{-# LANGUAGE OverloadedStrings #-}

-- | haskell representations of the sample data in /test/xml/.
--
-- NOTE: be reluctant to update anything in this module.  always prefer to add new definitions.
-- different parts of the test suite depend on this in different ways, and you may need to update
-- those depending tests as well.
module Samples where

import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.Types
import Data.List.NonEmpty (NonEmpty((:|)))
import SAML2.WebSSO
import Text.XML.DSig
import URI.ByteString.QQ


pubA, pubB :: SignCreds
privA, privB :: SignPrivCreds
(privA, pubA) = (SignPrivCreds SignDigestSha256 (SignPrivKeyRSA (KeyPair (PrivateKey {RSA.private_pub = PublicKey {public_size = 192, public_n = 1717663897341559205348709391423709685379493235767804963329162927305844911495579529578487198300729892496073075138715275063149122656660921722256202019363153057924617771262690016751408528982878438445044960173865402007802975054111572818917682802307758801558496603749817316616009067733882171100851083906679292052152723076832978037930580422994155492453752211395109708380791614773414010459142115626595108566788453085029627018015375094038148448417751806135336778818740891, public_e = 17}, private_d = 1515585791771964004719449463020920310628964619795122026466908465269863157201981937863371057324173434555358595710631125055719814108818460343167237075908664462874662739349432367721831054984892739804451435447528295889237919165392564249658571297761509880222157420356126206550212111498608439864421383700849735862144677780806062076024609223593605723485743018878935190766191244119559480385900117370608829639879419816245404301483989060411098357111528591771739596383023353, private_p = 1467496189976196609275204883355772389599762642052649087879370258198747771536511153342994462430534437654151050451903441860132169455473749721963405095449502964682330171958592524492698607436520850826894114096577169925406788528080173381, private_q = 1170472474868517661364846643990435226259339365982810184708469924180301819871877601582258311921234918982103685220599801596533480370038691816141174837238952351257574929682999252800586228039812669998678122880447516143387243374837807711, private_dP = 776909747634457028439814350011879500376344928145520105347901901399337055519329434122761774227929996405138791415713586867128795594074338088098273285826207451890645385154548983554958086289922803378943942757011442901685946867807150613, private_dQ = 275405288204357096791728622115396523825726909643014161107875276277718075263971200372296073393231745642847925934258776846243171851773809839092041138173871141472370571690117471247196759538779451764394852442458239092561704323491248873, private_qinv = 1445270686814272849353220262532419938474366819728263109337965566125321132986075922205247281835635620833761313576835811562836779463520550330671518241369444164154933513432356669655671381366493328276771298811284105325635266146121444242}))),SignCreds SignDigestSha256 (SignKeyRSA (PublicKey {public_size = 192, public_n = 1717663897341559205348709391423709685379493235767804963329162927305844911495579529578487198300729892496073075138715275063149122656660921722256202019363153057924617771262690016751408528982878438445044960173865402007802975054111572818917682802307758801558496603749817316616009067733882171100851083906679292052152723076832978037930580422994155492453752211395109708380791614773414010459142115626595108566788453085029627018015375094038148448417751806135336778818740891, public_e = 17})))
(privB, pubB) = (SignPrivCreds SignDigestSha256 (SignPrivKeyRSA (KeyPair (PrivateKey {private_pub = PublicKey {public_size = 192, public_n = 1821093174772066724891897029558011873762298648925334584517681972697371420407806727927774765666121128531444301316989919025460963256908086409968733368253778617307961481284915337602054109325842963713773149127211147108671492646903684465950540163781066141149436173688320361097404960356240833796538506471557148572907264956116404899356734515363147623354975438405236555098647579687930498800245099284586522389928166085565902347717541166365182284860181732586768683276925647, public_e = 17}, private_d = 1071231279277686308759939429151771690448410969956079167363342336880806717886945134075161626862424193253790765480582305309094684268769462594099254922502222716063506753697009022118855358426966449243395970074830086534512642733472755566618253346160111238544654685331326500204942614355746821833308408586904795173495750765693521344000796748259227567735807919987022885675496312456663437280467256608326384727969599901938806317533793802302034918425032747274927312006172433, private_p = 1377043509127984620263847708908504888389594729536495774985584923927826743836267308231044583339543580558100160458948740404822774142271268656903614192567220352247906074882774613270743664727539685972270679903157346862922117029117128839, private_q = 1322465966180892415359675499716560422359407786414975461694329287945992252941697180423392835275011799485222300299255361569604523507179035191607988462856230410802525593469605232981526266880370405730181043020380279199297275223749303673, private_dP = 486015356162818101269593309026531137078680492777586744112559384915703556648094344081545147061015381373447115456099555436996273226683977173024805009141371889028672732311567510566144822845014006813742592906996710657501923657335457237, private_dQ = 311168462630798215378747176403896569966919479156464814516312773634351118339222865981974784770591011643581717717471849781083417295806831809790114932436760096659417786698730643054476768677734213112983774828324771576305241229117483217, private_qinv = 1195631671016212299054116541862232633238180523696108484225023227028946134228318223061823169843059651662057797126995116563252609965177596252710448948327347393658475614810745236533411627325309619697858268077771236288990339417839693836}))),SignCreds SignDigestSha256 (SignKeyRSA (PublicKey {public_size = 192, public_n = 1821093174772066724891897029558011873762298648925334584517681972697371420407806727927774765666121128531444301316989919025460963256908086409968733368253778617307961481284915337602054109325842963713773149127211147108671492646903684465950540163781066141149436173688320361097404960356240833796538506471557148572907264956116404899356734515363147623354975438405236555098647579687930498800245099284586522389928166085565902347717541166365182284860181732586768683276925647, public_e = 17})))


azurewire :: IdPDesc
azurewire = undefined

common :: IdPDesc
common = undefined

-- source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference
microsoft_authnrequest_1 :: AuthnRequest
microsoft_authnrequest_1 = AuthnRequest {_rqID = ID {renderID = "id6c1c178c166d486687be4aaf5e482730"}, _rqVersion = Version_2_0, _rqIssueInstant = unsafeReadTime "2013-03-18T03:28:54.1839884Z", _rqIssuer = Issuer [uri|https://www.contoso.com|]}

-- source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-single-sign-on-protocol-reference
microsoft_authnresponse_0 :: AuthnResponse
microsoft_authnresponse_0 = undefined

microsoft_authnresponse_1 :: AuthnResponse
microsoft_authnresponse_1 = Response {_rspID = ID {renderID = "_ae75bd6c-6c76-4dc4-ae42-29153d6ca142"}, _rspInRespTo = Just ID {renderID = "id05873dd012c44e6db0bd59f5aa2e6a0a"}, _rspVersion = Version_2_0, _rspIssueInstant = unsafeReadTime "2018-04-13T06:33:02.772Z", _rspDestination = Just [uri|https://zb2.zerobuzz.net:60443/|], _rspIssuer = Just $ Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _rspStatus = StatusSuccess, _rspPayload = [Assertion {_assVersion = Version_2_0, _assID = ID {renderID = "_e9ae1025-bc03-4b5a-943c-c9fcb8730b21"}, _assIssueInstant = unsafeReadTime "2018-04-13T06:33:02.743Z", _assIssuer = Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _assConditions = Just Conditions {_condNotBefore = Just $ unsafeReadTime "2018-04-13T06:28:02.743Z", _condNotOnOrAfter = Just $ unsafeReadTime "2018-04-13T07:28:02.743Z", _condOneTimeUse = False, _condAudienceRestriction = Nothing}, _assContents = SubjectAndStatements Subject {_subjectID = opaqueNameID "E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84", _subjectConfirmations = [SubjectConfirmation {_scMethod = SubjectConfirmationMethodBearer, _scData = [SubjectConfirmationData {_scdNotBefore = Nothing, _scdNotOnOrAfter = unsafeReadTime "2018-04-13T06:38:02.743Z", _scdRecipient = [uri|https://zb2.zerobuzz.net:60443/|], _scdInResponseTo = Just ID {renderID = "id05873dd012c44e6db0bd59f5aa2e6a0a"}, _scdAddress = Nothing}]}]} (AttributeStatement {_attrstAttrs = Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/tenantid", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "682febe8-021b-4fde-ac09-e60085f05181"]} :| [Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/objectidentifier", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "66fbd626-b2b8-47d1-aad3-71ffc9b8ba86"]},Attribute {_stattrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "6ebceaad-1273-499a-b8bf-d26fcedcb662"]},Attribute {_stattrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "00182c01-2e4f-4dce-ae94-7d2cf4e5ef63"]},Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/displayname", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "00182c01-2e4f-4dce-ae94-7d2cf4e5ef63 6ebceaad-1273-499a-b8bf-d26fcedcb662"]},Attribute {_stattrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "azure@wire.com"]},Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/identityprovider", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "live.com"]},Attribute {_stattrName = "http://schemas.microsoft.com/claims/authnmethodsreferences", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",AttributeValueUntyped "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/unspecified"]}]} :| [AuthnStatement {_astAuthnInstant = unsafeReadTime "2018-03-27T06:23:57.851Z", _astSessionIndex = Just "_e9ae1025-bc03-4b5a-943c-c9fcb8730b21", _astSessionNotOnOrAfter = Nothing, _astSubjectLocality = Nothing}])}]}

microsoft_authnresponse_2 :: AuthnResponse
microsoft_authnresponse_2 = Response {_rspID = ID {renderID = "_3aeb3054-e85f-41fa-a20f-0f278b327f4e"}, _rspInRespTo = Just ID {renderID = "idcf2299ac551b42f1aa9b88804ed308c2"}, _rspVersion = Version_2_0, _rspIssueInstant = unsafeReadTime "2018-04-14T09:58:58.457Z", _rspDestination = Just $ [uri|https://zb2.zerobuzz.net:60443/authresp|], _rspIssuer = Just $ Issuer [uri|http://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _rspStatus = StatusSuccess, _rspPayload = [Assertion {_assVersion = Version_2_0, _assID = ID {renderID = "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6"}, _assIssueInstant = unsafeReadTime "2018-04-14T09:58:58.442Z", _assIssuer = Issuer [uri|https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/|], _assConditions = Just Conditions {_condNotBefore = Just (unsafeReadTime "2018-04-14T09:53:58.442Z"), _condNotOnOrAfter = Just (unsafeReadTime "2018-04-14T10:53:58.442Z"), _condOneTimeUse = False, _condAudienceRestriction = Nothing}, _assContents = SubjectAndStatements (Subject {_subjectID = opaqueNameID "xJxdqS8W2UXawbZZqpGFXKG4uEmO5GjijKD2RkMipBo", _subjectConfirmations = [SubjectConfirmation {_scMethod = SubjectConfirmationMethodBearer, _scData = [SubjectConfirmationData {_scdNotBefore = Nothing, _scdNotOnOrAfter = unsafeReadTime "2018-04-14T10:03:58.442Z", _scdRecipient = [uri|https://zb2.zerobuzz.net:60443/authresp|], _scdInResponseTo = Just ID {renderID = "idcf2299ac551b42f1aa9b88804ed308c2"}, _scdAddress = Nothing}]}]}) (AttributeStatement {_attrstAttrs = Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/tenantid", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "682febe8-021b-4fde-ac09-e60085f05181"]} :| [Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/objectidentifier", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "ccfb3788-8241-4afe-8897-f313f35f9e37"]},Attribute {_stattrName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "fisxt1@azurewire.onmicrosoft.com"]},Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/displayname", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "fisxt1"]},Attribute {_stattrName = "http://schemas.microsoft.com/identity/claims/identityprovider", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "https://sts.windows.net/682febe8-021b-4fde-ac09-e60085f05181/"]},Attribute {_stattrName = "http://schemas.microsoft.com/claims/authnmethodsreferences", _stattrNameFormat = Nothing, _stattrFriendlyName = Nothing, _stattrValues = [AttributeValueUntyped "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"]}]} :| [AuthnStatement {_astAuthnInstant = unsafeReadTime "2018-04-14T09:58:55.613Z", _astSessionIndex = Just "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6", _astSessionNotOnOrAfter = Nothing, _astSubjectLocality = Nothing}])}]}

microsoft_idp_keyinfo :: RSA.PublicKey
microsoft_idp_keyinfo = RSA.PublicKey {RSA.public_size = 256, RSA.public_n = 25266449847616032605280887180445946447207827183577848474184616846136744459013940059297388901949168945284876940449831022307515873851064478442088422354857937225651881330471758496854838771727042040743247357142715828206862944363464254559789249948813601166263148331870847174783313061359856986236119735646527697584352746595070831856826144035963401689203402892945174546914103842786133972997748592644348449313622309013132898328267351769300154913558618070904948090075390540412224001257219178211139174816497946208851160331679253663348572295658494523941468674192526945936020222447823781738913444250167710107767554511823728989391, RSA.public_e = 65537}

microsoft_meta_2 :: IdPDesc
microsoft_meta_2 = undefined

onelogin_request_1 :: AuthnRequest
onelogin_request_1 = AuthnRequest
  { _rqID = ID "pfx41d8ef22-e612-8c50-9960-1b16f15741b3"
  , _rqVersion = Version_2_0
  , _rqIssueInstant = unsafeReadTime "2014-07-16T23:52:45Z"
  , _rqIssuer = Issuer [uri|http://sp.example.com/demo1/metadata.php|]
  }

onelogin_response_1 :: AuthnResponse
onelogin_response_1 = undefined

onelogin_response_2 :: AuthnResponse
onelogin_response_2 = undefined

onelogin_response_3 :: AuthnResponse
onelogin_response_3 = undefined
