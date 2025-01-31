#!/usr/bin/env bash

set -e

flag_skip_redis=true
cloneDir=$(dirname $0)

# For legacy mode, when called from the install script...
SUDO="$1"


if [ "$flag_skip_redis" == true ]; then
    $SUDO patch -p1 < $cloneDir/patches/docker-compose-redis.patch
fi
$SUDO patch -p1 < $cloneDir/patches/docker-compose.patch
if [ "$SUDO" == "" ]; then
    # TODO: should incorporate this into docker-compose.patch
    $SUDO patch -p1 < $cloneDir/build/tmp.patch
fi

$SUDO patch -p1 < $cloneDir/patches/bad-key-revoker_main.patch
$SUDO patch -p1 < $cloneDir/patches/boulder-va_main.patch
$SUDO patch -p1 < $cloneDir/patches/ca_ca.patch
$SUDO patch -p1 < $cloneDir/patches/ca_ca_keytype_hack.patch
$SUDO patch -p1 < $cloneDir/patches/ca_crl.patch
$SUDO patch -p1 < $cloneDir/patches/ceremony_ecdsa.patch
$SUDO patch -p1 < $cloneDir/patches/ceremony_key.patch
$SUDO patch -p1 < $cloneDir/patches/ceremony_main.patch
$SUDO patch -p1 < $cloneDir/patches/ceremony_rsa.patch
$SUDO patch -p1 < $cloneDir/patches/cert-checker_main.patch
$SUDO patch -p1 < $cloneDir/patches/cmd_config.patch
$SUDO patch -p1 < $cloneDir/patches/config_duration.patch
$SUDO patch -p1 < $cloneDir/patches/contact-auditor_main.patch
$SUDO patch -p1 < $cloneDir/patches/core_interfaces.patch
$SUDO patch -p1 < $cloneDir/patches/crl-storer_main.patch
$SUDO patch -p1 < $cloneDir/patches/db_migrations.patch
$SUDO patch -p1 < $cloneDir/patches/db_migrations2.patch
$SUDO patch -p1 < $cloneDir/patches/db_migrations3.patch
$SUDO patch -p1 < $cloneDir/patches/db_migrations4.patch
$SUDO patch -p1 < $cloneDir/patches/db_migrations5.patch
$SUDO patch -p1 < $cloneDir/patches/errors_errors.patch
$SUDO patch -p1 < $cloneDir/patches/expiration-mailer_main.patch
$SUDO patch -p1 < $cloneDir/patches/issuance_crl.patch
$SUDO patch -p1 < $cloneDir/patches/linter_linter.patch
$SUDO patch -p1 < $cloneDir/patches/log_prod_prefix.patch
$SUDO patch -p1 < $cloneDir/patches/log_test_prefix.patch
$SUDO patch -p1 < $cloneDir/patches/log_validator_validator.patch
$SUDO patch -p1 < $cloneDir/patches/mail_mailer.patch
$SUDO patch -p1 < $cloneDir/patches/makefile.patch
$SUDO patch -p1 < $cloneDir/patches/notify-mailer_main.patch
$SUDO patch -p1 < $cloneDir/patches/ocsp-responder_main.patch
$SUDO patch -p1 < $cloneDir/patches/policy_pa.patch
$SUDO patch -p1 < $cloneDir/patches/ra_ra.patch
$SUDO patch -p1 < $cloneDir/patches/ratelimit_rate-limits.patch
$SUDO patch -p1 < $cloneDir/patches/ratelimits_names.patch
$SUDO patch -p1 < $cloneDir/patches/remoteva_main.patch
$SUDO patch -p1 < $cloneDir/patches/start.patch
if [ "$SUDO" == "" ]; then
    # TODO: should include this into startservers.patch
    $SUDO patch -p1 < $cloneDir/build/tmp2.patch
fi
$SUDO patch -p1 < $cloneDir/patches/sfe_templates_layout.patch
$SUDO patch -p1 < $cloneDir/patches/storer_storer.patch
$SUDO patch -p1 < $cloneDir/patches/test_health-checker_main.patch
$SUDO patch -p1 < $cloneDir/patches/updater_updater.patch
$SUDO patch -p1 < $cloneDir/patches/updater_continuous.patch
$SUDO patch -p1 < $cloneDir/patches/va_http.patch
$SUDO patch -p1 < $cloneDir/patches/va_va.patch
$SUDO patch -p1 < $cloneDir/patches/wfe2_main.patch
$SUDO patch -p1 < $cloneDir/patches/wfe2_wfe.patch

sed -i -e "s|./test|./labca|" start.py

sed -i -e "s/berrors.RateLimitError(/berrors.RateLimitError(ra.rlPolicies.RateLimitsURL(), /g" ra/ra.go
sed -i -e "s/berrors.RateLimitError(/berrors.RateLimitError(\"\", /g" ratelimits/limiter.go

sed -i -e "s/proxysql:6033/mysql:3306/" sa/db/dbconfig.yml

mkdir -p "cmd/mail-tester"
cp $cloneDir/mail-tester.go cmd/mail-tester/main.go
perl -i -p0e "s/(\n\t\"github.com\/letsencrypt\/boulder\/cmd\")/\t_ \"github.com\/letsencrypt\/boulder\/cmd\/mail-tester\"\n\1/igs"  cmd/boulder/main.go

perl -i -p0e "s/If you continue to encounter.*for troubleshooting and advice.//igs" sfe/pages/index.html
perl -i -p0e "s/<b>Note:<\/b> If you encounter.*troubleshooting and advice.//igs" sfe/pages/unpause-form.html
perl -i -p0e "s/If you continue to encounter.*for troubleshooting and advice.//igs" sfe/pages/unpause-invalid-request.html
perl -i -p0e "s/ If you face continued.*for troubleshooting and advice.//igs" sfe/pages/unpause-status.html
