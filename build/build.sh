#!/bin/bash -e

set -euo pipefail

cd $(dirname $0)

TMP_DIR=$(pwd)/tmp
rm -rf $TMP_DIR && mkdir -p $TMP_DIR/{admin,bin,logs,src}

boulderDir=$TMP_DIR/src
boulderTag="release-2025-01-06"
boulderUrl="https://github.com/letsencrypt/boulder/"
cloneDir=$(pwd)/..

GIT_VERSION=$(git describe --always --tags 2>/dev/null)
BUILD_HOST=labca-$GIT_VERSION
BUILD_IMAGE=$(eval echo $(grep boulder-tools ../patches/docker-compose.patch | head -3 | tail -1 | sed -e "s/\+\s*image://" | sed -e "s/&boulder_tools_image//"))

git clone --branch $boulderTag --depth 1 $boulderUrl $boulderDir 2>/dev/null
cd $boulderDir
if [ $boulderTag != "main" ]; then
    git checkout $boulderTag -b $boulderTag 2>/dev/null
fi

if [ "$BUILD_IMAGE" == "" ]; then
    BUILD_IMAGE=$(eval echo $(grep boulder-tools $TMP_DIR/src/docker-compose.yml | grep "image:" | head -1 | sed -e "s/image://" | sed -e "s/&boulder_tools_image//"))
fi

BOULDER_TOOLS_TAG=$(grep go1. $TMP_DIR/src/.github/workflows/boulder-ci.yml | head -1 | sed -e "s/\s*- //")
BUILD_IMAGE=${BUILD_IMAGE/latest/$BOULDER_TOOLS_TAG}

echo
$cloneDir/patch.sh
cp -r test labca
$cloneDir/patch-cfg.sh " " "$boulderDir/labca"
sed -i "s/BUILD_ID = .*/BUILD_ID = \$(shell git describe --always HEAD 2>\/dev\/null) +\$(COMMIT_ID)/" $boulderDir/Makefile
sed -i "s/BUILD_HOST = .*/BUILD_HOST ?= labca-develop/" $boulderDir/Makefile
sed -i "s/-ldflags \"-X/-ldflags \"-s -w -X/" $boulderDir/Makefile
cp -p docker-compose.yml $cloneDir/build/

echo
BASEDIR=/go/src/github.com/letsencrypt/boulder
docker run -v $boulderDir:$BASEDIR:cached -v $TMP_DIR/bin:$BASEDIR/bin -w $BASEDIR -e BUILD_HOST=$BUILD_HOST $BUILD_IMAGE sh -c "git config --global --add safe.directory $BASEDIR && make build"

cp $cloneDir/nginx.conf $TMP_DIR/
cp $cloneDir/proxy.inc $TMP_DIR/
cp -rp $cloneDir/gui/* $TMP_DIR/admin/
head -13 $cloneDir/gui/setup.sh > $TMP_DIR/admin/setup.sh
sed -i '/^$/d' $TMP_DIR/admin/setup.sh

echo
BASEDIR=/go/src/labca
docker run -v $TMP_DIR/admin:$BASEDIR:cached -v $TMP_DIR:$BASEDIR/bin -w $BASEDIR -e GIT_VERSION=$GIT_VERSION $BUILD_IMAGE ./setup.sh

cp -rp $cloneDir/gui/setup.sh $TMP_DIR/admin/
cp -rp $cloneDir/acme_tiny.py $TMP_DIR/
cp -rp $cloneDir/backup $TMP_DIR/
cp -rp $cloneDir/checkcrl $TMP_DIR/
cp -rp $cloneDir/checkrenew $TMP_DIR/
cp -rp $cloneDir/commander $TMP_DIR/
cp -rp $cloneDir/control_do.sh $TMP_DIR/control.sh
cp -rp $cloneDir/cron_d $TMP_DIR/
cp -rp $cloneDir/mailer $TMP_DIR/
cp -rp $cloneDir/renew $TMP_DIR/
cp -rp $cloneDir/restore $TMP_DIR/
cp -rp $cloneDir/utils.sh $TMP_DIR/

echo
