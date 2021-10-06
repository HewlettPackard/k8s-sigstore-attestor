#!/bin/bash

set -e

COVERPROFILE=
if [ -n "${COVERALLS_TOKEN}" ]; then
    COVERPROFILE=profile.cov
    go get github.com/mattn/goveralls@v0.0.7
    go get github.com/google/go-containerregistry/pkg/name
    go get github.com/sigstore/cosign/pkg/cosign
fi

COVERPROFILE="${COVERPROFILE}" make test

if [ -n "${COVERALLS_TOKEN}" ]; then
    "$(go env GOPATH)"/bin/goveralls -coverprofile="${COVERPROFILE}" \
            -service=github
fi
