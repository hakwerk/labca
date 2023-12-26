#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca-gui ] || set -ev
if [ ! -e bin/labca-gui ]; then
    go mod download

    go build -buildvcs=false -o bin/labca-gui -ldflags="-X 'main.standaloneVersion=$GIT_VERSION'"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y iproute2 zip unzip
apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg
install -m 0755 -d /etc/apt/keyrings
[ ! -e /etc/apt/keyrings/docker.gpg ] || mv /etc/apt/keyrings/docker.gpg /etc/apt/keyrings/docker.gpg_PREV
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

dcver=$(docker compose version | grep v2.19 | wc -l)
if [ "$dcver" != "0" ]; then
    dc18=$(apt list docker-compose-plugin -a 2>/dev/null | grep 2.18 | cut -d ' ' -f 2)
    apt install -y --allow-downgrades docker-compose-plugin=${dc18}
fi

bin/labca-gui
