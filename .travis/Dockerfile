FROM quay.io/wire/alpine-builder
WORKDIR /src/saml2-web-sso

RUN apk add --no-cache git ncurses && \
    mkdir -p /src && cd /src && \
    git clone https://github.com/wireapp/saml2-web-sso && \
    cd saml2-web-sso && \
    mkdir -p /src/.stack-docker && ln -s /src/.stack-docker && \
    stack update && \
    echo -e "allow-different-user: true\n" >> /root/.stack/config.yaml && \
    for RESOLVER in lts-10.3 lts-11.13 && do \
        stack --resolver $RESOLVER --work-dir .stack-docker build --test --dependencies-only --no-run-tests && \
    done
