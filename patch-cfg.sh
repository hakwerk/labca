#!/usr/bin/env bash

set -e

cloneDir=$(dirname $0)

# For legacy mode, when called from the install script...
SUDO="$1"
boulderLabCADir="${2:-labca}"

[ -d "$boulderLabCADir/config" ] || mkdir -p "$boulderLabCADir/config"


$SUDO patch -p1 -o "$boulderLabCADir/entrypoint.sh" < $cloneDir/patches/entrypoint.patch
cp test/startservers.py "$boulderLabCADir/startservers.py"

$SUDO patch -p1 -o "$boulderLabCADir/config/bad-key-revoker.json" < $cloneDir/patches/config_bad-key-revoker.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/publisher.json" < $cloneDir/patches/config_publisher.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/wfe2.json" < $cloneDir/patches/config_wfe2.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/crl-storer.json" < $cloneDir/patches/config_crl-storer.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/crl-updater.json" < $cloneDir/patches/config_crl-updater.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/ca.json" < $cloneDir/patches/test_config_ca.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/ra.json" < $cloneDir/patches/config_ra.patch
$SUDO patch -p1 -o "$boulderLabCADir/config/akamai-purger.json" < $cloneDir/patches/config_akamai-purger.patch
$SUDO patch -p1 -o "$boulderLabCADir/certs/generate.sh" < $cloneDir/patches/test_certs_generate.patch
chmod +x $boulderLabCADir/certs/generate.sh

cp test/config/va*.json "$boulderLabCADir/config/"
perl -i -p0e "s/\"dnsProvider\": \{.*?\t\t},/\"dnsStaticResolvers\": [\n\t\t\t\"127.0.0.1:8053\",\n\t\t\t\"127.0.0.1:8054\"\n\t\t],\n\t\t\"dnsAllowLoopbackAddresses\": true,/igs" $boulderLabCADir/config/va.json
perl -i -p0e "s/\"dnsProvider\": \{.*?\t\t},/\"dnsStaticResolvers\": [\n\t\t\t\"127.0.0.1:8053\",\n\t\t\t\"127.0.0.1:8054\"\n\t\t],\n\t\t\"dnsAllowLoopbackAddresses\": true,/igs" $boulderLabCADir/config/remoteva-a.json
perl -i -p0e "s/\"dnsProvider\": \{.*?\t\t},/\"dnsStaticResolvers\": [\n\t\t\t\"127.0.0.1:8053\",\n\t\t\t\"127.0.0.1:8054\"\n\t\t],\n\t\t\"dnsAllowLoopbackAddresses\": true,/igs" $boulderLabCADir/config/remoteva-b.json
perl -i -p0e "s/\"dnsProvider\": \{.*?\t\t},/\"dnsStaticResolvers\": [\n\t\t\t\"127.0.0.1:8053\",\n\t\t\t\"127.0.0.1:8054\"\n\t\t],\n\t\t\"dnsAllowLoopbackAddresses\": true,/igs" $boulderLabCADir/config/remoteva-c.json
perl -i -p0e "s/(\"accountURIPrefixes\": \[\n.*?\s+\])/\1,\n\t\t\"labcaDomains\": [\n\t\t]/igs" $boulderLabCADir/config/remoteva-a.json
perl -i -p0e "s/(\"accountURIPrefixes\": \[\n.*?\s+\])/\1,\n\t\t\"labcaDomains\": [\n\t\t]/igs" $boulderLabCADir/config/remoteva-b.json
perl -i -p0e "s/(\"accountURIPrefixes\": \[\n.*?\s+\])/\1,\n\t\t\"labcaDomains\": [\n\t\t]/igs" $boulderLabCADir/config/remoteva-c.json
perl -i -p0e "s/(\"accountURIPrefixes\": \[\n.*?\s+\])/\1,\n\t\t\"labcaDomains\": [\n\t\t]/igs" $boulderLabCADir/config/va.json

for f in $(grep -l boulder-proxysql $boulderLabCADir/secrets/*); do sed -i -e "s/proxysql:6033/mysql:3306/" $f; done

cd "$boulderLabCADir"
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/publisher.json
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/ca.json
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/wfe2.json
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/crl-storer.json
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/crl-updater.json
sed -i -e "s|test/certs/webpki/int-rsa-a.cert.pem|labca/certs/webpki/issuer-01-cert.pem|" config/ra.json
sed -i -e "s|test/certs/webpki/int-rsa-a.pkcs11.json|labca/certs/webpki/issuer-01.pkcs11.json|" config/ca.json
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" certs/root-ceremony-rsa.yaml
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" certs/root-crl-rsa.yaml
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" certs/intermediate-cert-ceremony-rsa.yaml
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" config/publisher.json
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" config/wfe2.json
sed -i -e "s|test/certs/webpki/root-rsa.cert.pem|labca/certs/webpki/root-01-cert.pem|" helpers.py
sed -i -e "s|letsencrypt/boulder|hakwerk/labca|" config/wfe2.json
sed -i -e "s|1.2.3.4|1.3.6.1.4.1.44947.1.1.1|g" config/ca.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/remoteva-a.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/remoteva-b.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/remoteva-c.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/ra.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/va.json
sed -i -e "s/\"stdoutlevel\": 4,/\"stdoutlevel\": 6,/" config/ca.json
sed -i -e "s/\"stdoutlevel\": 4,/\"stdoutlevel\": 6,/" config/remoteva-a.json
sed -i -e "s/\"stdoutlevel\": 4,/\"stdoutlevel\": 6,/" config/remoteva-b.json
sed -i -e "s/\"stdoutlevel\": 4,/\"stdoutlevel\": 6,/" config/remoteva-c.json
sed -i -e "s/\"endpoint\": \".*\"/\"endpoint\": \"\"/" config/sfe.json
sed -i -e "s/sleep 1/sleep 5/g" wait-for-it.sh

perl -i -p0e "s/(services {\s*id\s*=\s*\"bredis4\".*?}\n\n)//igs" consul/config.hcl

sed -i -e "s|test/certs|/opt/boulder/labca/certs|" consul/config.hcl
sed -i -e "s|/test/certs|/opt/boulder/labca/certs|" redis-ratelimits.config

perl -i -p0e "s/(\s*)(\"passwordFile\":.*?,).*(\"lookups\": \[)/\1\2\1\"db\": 1,\1\3/igs" config/ra.json
perl -i -p0e "s/,(\s*)(\"passwordFile\":.*?,).*(\"lookups\": \[)/,\1\2\1\"db\": 1,\1\3/igs" config/wfe2.json

for file in `find . -type f | grep -v .git`; do
    sed -i -e "s|test/|labca/|g" $file
done

rm -f test-ca2.pem
