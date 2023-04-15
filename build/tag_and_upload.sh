#!/bin/bash -e

set -euo pipefail

cd $(dirname $0)

REPO_BASE="hakwerk/labca"

BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ "$BRANCH" == "master" ] || [ "$BRANCH" == "main" ]; then
    TAG=$(git describe --always --tags 2>/dev/null)
    [[ $TAG == v* ]] && TAG="${TAG:1}" || /bin/true
else
    TAG=$BRANCH
fi

LABCA_GUI_TAG="${REPO_BASE}-gui:$TAG"
LABCA_GUI_LATEST="${REPO_BASE}-gui:latest"
LABCA_BOULDER_TAG="${REPO_BASE}-boulder:$TAG"
LABCA_BOULDER_LATEST="${REPO_BASE}-boulder:latest"
LABCA_CONTROL_TAG="${REPO_BASE}-control:$TAG"
LABCA_CONTROL_LATEST="${REPO_BASE}-control:latest"

die() {
    echo $1
    exit 1
}

cp -rp ../gui/setup.sh tmp/admin/
[ -f "tmp/labca-gui" ] || die "LabCA binary does not exist!"
docker build -f Dockerfile-gui -t $LABCA_GUI_TAG .

if [ "$BRANCH" == "master" ] || [ "$BRANCH" == "main" ]; then
    ID="$(docker images | grep "${REPO_BASE}-gui" | grep -v latest | head -n 1 | awk '{print $3}')"
    docker tag "$ID" $LABCA_GUI_LATEST
fi

cnt=$(ls -1 tmp/bin | wc -l)
[ $cnt -gt 20 ] || die "Only found $cnt boulder binaries!"  # ?? still correct??
docker build -f Dockerfile-boulder -t $LABCA_BOULDER_TAG .

if [ "$BRANCH" == "master" ] || [ "$BRANCH" == "main" ]; then
    ID="$(docker images | grep "${REPO_BASE}-boulder" | grep -v latest | head -n 1 | awk '{print $3}')"
    docker tag "$ID" $LABCA_BOULDER_LATEST
fi

cp -rp ../acme_tiny.py tmp/
cp -rp ../backup tmp/
cp -rp ../checkcrl tmp/
cp -rp ../checkrenew tmp/
cp -rp ../commander tmp/
cp -rp ../control_do.sh tmp/control.sh
cp -rp ../cron_d tmp/
cp -rp ../mailer tmp/
cp -rp ../renew tmp/
cp -rp ../restore tmp/
cp -rp ../utils.sh tmp/
docker build -f Dockerfile-control -t $LABCA_CONTROL_TAG .

if [ "$BRANCH" == "master" ] || [ "$BRANCH" == "main" ]; then
    ID="$(docker images | grep "${REPO_BASE}-control" | grep -v latest | head -n 1 | awk '{print $3}')"
    docker tag "$ID" $LABCA_CONTROL_LATEST
fi

echo
if [ "$BRANCH" != "master" ] || [ "$BRANCH" == "main" ]; then
    echo "Not pushing to Dockerhub..."
    exit
fi

echo "Image ready, please login to allow Dockerhub push"
echo TODO docker login

echo
echo "Pushing ${LABCA_GUI_TAG} to Dockerhub"
echo TODO docker push ${LABCA_GUI_TAG}
echo "Pushing ${LABCA_BOULDER_TAG} to Dockerhub"
echo TODO docker push ${LABCA_BOULDER_TAG}
echo "Pushing ${LABCA_CONTROL_TAG} to Dockerhub"
echo TODO docker push ${LABCA_CONTROL_TAG}

if [ "$BRANCH" == "master" ] || [ "$BRANCH" == "main" ]; then
    echo "Pushing ${LABCA_GUI_LATEST} to Dockerhub"
    echo TODO docker push ${LABCA_GUI_LATEST}
    echo "Pushing ${LABCA_BOULDER_LATEST} to Dockerhub"
    echo TODO docker push ${LABCA_BOULDER_LATEST}
    echo "Pushing ${LABCA_CONTROL_LATEST} to Dockerhub"
    echo TODO docker push ${LABCA_CONTROL_LATEST}
fi
