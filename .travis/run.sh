#!/bin/sh

export IMAGE=quay.io/wire/alpine-saml2-web-sso
docker pull $IMAGE

export VOLUMES="-v `pwd`:/src/saml2-web-sso"
[ "$1" = "--connect" ] && export CONNECT_TO_RUNNING_CONTAINER=1
[ "$1" != "" ] && export RUN_CMD="$1"

if [ "$CONNECT_TO_RUNNING_CONTAINER" = "1" ]; then
    docker exec -it `docker ps -q --filter="ancestor=$IMAGE"` /bin/bash
else
    docker run -it --rm $VOLUMES $IMAGE /bin/bash -c "$RUN_CMD"
fi
