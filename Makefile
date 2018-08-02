
.PHONY: test
test:
	export SAML2_WEB_SSO_ROOT=$$(pwd) && stack build --test
