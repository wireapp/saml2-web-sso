
.PHONY: test
test:
	export SAML2_WEB_SSO_ROOT=$$(pwd) && stack build --test

# formats all Haskell files (which don't contain CPP)
.PHONY: format
format:
	./tools/ormolu.sh
