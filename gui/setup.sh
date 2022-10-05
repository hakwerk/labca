#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca-gui ] || set -ev
if [ ! -e bin/labca-gui ]; then
    go mod download

    go build -buildvcs=false -o bin/labca-gui
fi

export DEBIAN_FRONTEND=noninteractive
[ -e /bin/ip ] || (apt update && apt install -y iproute2)
[ -e /bin/zip ] || (apt update && apt install -y zip)

bin/labca-gui
