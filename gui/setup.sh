#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca ] || set -ev
if [ ! -e bin/labca ]; then
    go mod download

    go build -o bin/labca
fi

bin/labca
