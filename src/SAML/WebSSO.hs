{- |

Relevant parts of the standard are referenced throughout the code, using the notation
@[<file>/<paragraph>]@.  <file> is one of these:

[1] http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
[2] http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
[3] http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
[4] http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
[5] http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
[6] http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf
[7] http://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf
[8] http://docs.oasis-open.org/security/saml/v2.0/saml-glossary-2.0-os.pdf

TODO: move SAML.* to SAML2.* for consistency with package name.

-}
module SAML.WebSSO (module X) where

import SAML.WebSSO.API as X
import SAML.WebSSO.Config as X
import SAML.WebSSO.SP as X
import SAML.WebSSO.Types as X
import SAML.WebSSO.XML as X
import SAML.WebSSO.XML.Meta as X
