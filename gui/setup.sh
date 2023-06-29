#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca-gui ] || set -ev
if [ ! -e bin/labca-gui ]; then
    go mod download

    go build -buildvcs=false -o bin/labca-gui -ldflags="-X 'main.standaloneVersion=$GIT_VERSION'"
fi

export DEBIAN_FRONTEND=noninteractive
apt update
[ -e /bin/ip ] || apt install -y iproute2
[ -e /bin/zip ] || apt install -y zip
apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
apt update
apt install -y docker-ce

bin/labca-gui
