#!/usr/bin/env bash

set -e

flag_skip_redis=true
cloneDir=$(dirname $0)

# For legacy mode, when called from the install script...
SUDO="$1"
boulderLabCADir="${2:-labca}"

[ -d "$boulderLabCADir/config" ] || mkdir -p "$boulderLabCADir/config"


$SUDO patch -p1 -o "$boulderLabCADir/entrypoint.sh" < $cloneDir/patches/entrypoint.patch
cp test/startservers.py "$boulderLabCADir/startservers.py"

$SUDO patch -p1 -o "$boulderLabCADir/config/ca-a.json" < $cloneDir/patches/test_config_ca_a.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/ca-b.json" < $cloneDir/patches/test_config_ca_b.patch

$SUDO patch -p1 -o "$boulderLabCADir/config/expiration-mailer.json" < $cloneDir/patches/config_expiration-mailer.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/notify-mailer.json" < $cloneDir/patches/config_notify-mailer.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/bad-key-revoker.json" < $cloneDir/patches/config_bad-key-revoker.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/ocsp-responder.json" < $cloneDir/patches/config_ocsp-responder.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/publisher.json" < $cloneDir/patches/config_publisher.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/wfe2.json" < $cloneDir/patches/config_wfe2.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/orphan-finder.json" < $cloneDir/patches/config_orphan-finder.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/crl-storer.json" < $cloneDir/patches/config_crl-storer.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/crl-updater.json" < $cloneDir/patches/config_crl-updater.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/ra.json" < $cloneDir/patches/config_ra.patch

cp test/config/va*.json "$boulderLabCADir/config/"
perl -i -p0e "s/\"dnsResolver\": \"service.consul\",/\"dnsResolvers\": [\n      \"127.0.0.1:8053\",\n      \"127.0.0.1:8054\"\n    ],/igs" $boulderLabCADir/config/va.json
perl -i -p0e "s/\"dnsResolver\": \"service.consul\",/\"dnsResolvers\": [\n      \"127.0.0.1:8053\",\n      \"127.0.0.1:8054\"\n    ],/igs" $boulderLabCADir/config/va-remote-a.json
perl -i -p0e "s/\"dnsResolver\": \"service.consul\",/\"dnsResolvers\": [\n      \"127.0.0.1:8053\",\n      \"127.0.0.1:8054\"\n    ],/igs" $boulderLabCADir/config/va-remote-b.json

if [ "$flag_skip_redis" == true ]; then
    perl -i -p0e "s/\n    \"redis\": \{\n.*?    \},//igs" $boulderLabCADir/config/ocsp-responder.json
fi

for f in $(grep -l boulder-proxysql $boulderLabCADir/secrets/*); do sed -i -e "s/proxysql:6033/mysql:3306/" $f; done
