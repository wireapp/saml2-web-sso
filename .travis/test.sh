#!/bin/sh

ln -s /src/.stack-docker
for RESOLVER in lts-10.3 lts-11.13; do
    stack --resolver $RESOLVER --work-dir .stack-docker build --test --dependencies-only --no-run-tests
