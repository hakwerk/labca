#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca ] || set -ev
if [ ! -e bin/labca ]; then
    go mod download

    go build -o bin/labca
fi

[ -e /bin/ip ] || (apt update && apt install -y iproute2)
[ -e /bin/zip ] || (apt update && apt install -y zip)

bin/labca
