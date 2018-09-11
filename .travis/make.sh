#!/bin/sh

export IMAGE=quay.io/wire/alpine-saml2-web-sso

docker build .

export GIT_HASH=`docker run -it --rm $IMAGE:latest /bin/sh -c "cd /src/saml2-web-sso && git rev-parse --short HEAD"`
GIT_HASH=${GIT_HASH:0:7}  # Remove trailing '\r' character from the end.
docker tag $IMAGE:latest $IMAGE:$GIT_HASH

docker login quay.io
docker push $IMAGE:$GIT_HASH
