#!/bin/bash

set -e

get_fqdn() {
    local file_fqdn=""
    if [ -e /opt/labca/data/config.json ]; then
        file_fqdn=$(grep fqdn /opt/labca/data/config.json 2>/dev/null | cut -d ":" -f 2- | tr -d " \",")
    fi
    if [ "$file_fqdn" == "" ]; then
        if [ "$LABCA_FQDN" == "notset" ]; then
            echo "ERROR: environment variable LABCA_FQDN is not set!"
            exit 1
        else
            echo -e "{\n  \"config\": {\n    \"complete\": false\n  },\n  \"labca\": {\n    \"fqdn\": \"$LABCA_FQDN\"\n  },\n  \"version\": \"\"\n}" > /opt/labca/data/config.json
        fi
    elif [ "$LABCA_FQDN" != "notset" ] && [ "$LABCA_FQDN" != "$file_fqdn" ]; then
        echo "WARNING: environment variable LABCA_FQDN ('$LABCA_FQDN') does not match config file. Using '$file_fqdn'..."
        export LABCA_FQDN=$file_fqdn
    fi
}

setup_boulder_data() {
    cp -rp /opt/staging/boulder_labca/* /opt/boulder/labca/
    cp -rp /opt/staging/boulder_labca/certs/* /opt/boulder/labca/certs/

    cd /opt/boulder/labca

    sed -i -e "s|https://boulder.service.consul:4431/terms/v7|https://$LABCA_FQDN/terms/v1|" config/wfe2.json
    sed -i -e "s|boulder.service.consul:4000|$LABCA_FQDN|g" config/wfe2.json
    sed -i -e "s|http://ca.example.org:4002/|http://$LABCA_FQDN/ocsp/|g" config/ca.json
    sed -i -e "s|http://ca.example.org:4501/rsa-a/|http://$LABCA_FQDN/crl/|g" config/ca.json
    sed -i -e "s|boulder.service.consul:4000|$LABCA_FQDN|g" config/remoteva-a.json
    sed -i -e "s|boulder.service.consul:4001|$LABCA_FQDN|g" config/remoteva-a.json
    sed -i -e "s|boulder.service.consul:4000|$LABCA_FQDN|g" config/remoteva-b.json
    sed -i -e "s|boulder.service.consul:4001|$LABCA_FQDN|g" config/remoteva-b.json
    sed -i -e "s|boulder.service.consul:4000|$LABCA_FQDN|g" config/va.json
    sed -i -e "s|boulder.service.consul:4001|$LABCA_FQDN|g" config/va.json

    /opt/labca/apply-boulder
}

setup_nginx_data() {
    rm -f /etc/nginx/conf.d/default.conf
    cp -p /opt/staging/nginx.conf /etc/nginx/conf.d/labca.conf
    cp -p /opt/staging/proxy.inc /etc/nginx/conf.d/proxy.inc
    [ -e /opt/boulder/labca/setup_complete ] && perl -i -p0e 's/\n    # BEGIN temporary redirect\n    location = \/ \{\n        return 302 \/admin\/;\n    }\n    # END temporary redirect\n//igs' /etc/nginx/conf.d/labca.conf || true

    cd /var/www/html
    mkdir -p .well-known/acme-challenge
    find .well-known/acme-challenge/ -type f -mtime +10 -exec rm {} \;  # Clean up files older than 10 days
    mkdir -p crl
    [ -e cert ] || ln -s certs cert
    cp -rp /opt/staging/static/* .

    [ -e /opt/labca/data/root-ca.pem ] && cp /opt/labca/data/root-ca.pem certs/ || true
    [ -e /opt/labca/data/issuer/ca-int.pem ] && cp /opt/labca/data/issuer/ca-int.pem certs/ || true

    if [ ! -e /etc/nginx/ssl/labca_cert.pem ]; then
        pushd /etc/nginx/ssl >/dev/null
        openssl req -x509 -nodes -sha256 -newkey rsa:2048 -keyout labca_key.pem -out labca_cert.pem -days 7 \
            -subj "/O=LabCA/CN=$LABCA_FQDN" -reqexts SAN -extensions SAN \
            -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nbasicConstraints=CA:FALSE\nnsCertType=server\nsubjectAltName=DNS:$LABCA_FQDN"))
        popd >/dev/null
    fi

    /opt/labca/apply-nginx
}

setup_labca_data() {
    cd /opt/labca/data
    cp -rp /opt/staging/data/* .

    sed -i -e "s|LABCA_FQDN|$LABCA_FQDN|g" openssl.cnf
    sed -i -e "s|LABCA_FQDN|$LABCA_FQDN|g" issuer/openssl.cnf
}

selfsigned_cert() {
    pushd /etc/nginx/ssl >/dev/null
    openssl req -x509 -nodes -sha256 -newkey rsa:2048 -keyout labca_key.pem -out labca_cert.pem -days 7 \
        -subj "/O=LabCA/CN=$LABCA_FQDN" -reqexts SAN -extensions SAN \
        -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nbasicConstraints=CA:FALSE\nnsCertType=server\nsubjectAltName=DNS:$LABCA_FQDN"))
    popd >/dev/null
}

renew_near_expiry() {
    pushd /etc/nginx/ssl >/dev/null
    if ! expires=$(openssl x509 -checkend 86400 -noout -in /etc/nginx/ssl/labca_cert.pem); then
        hash=$(openssl x509 -hash -noout -in /etc/nginx/ssl/labca_cert.pem)
        issuer_hash=$(openssl x509 -issuer_hash -noout -in /etc/nginx/ssl/labca_cert.pem)
        if [ "$hash" == "$issuer_hash" ]; then
            selfsigned_cert
        else
            echo "acme-request" | /opt/labca/commander
        fi
    fi
    popd >/dev/null
}

start_cron() {
    [ -e /opt/boulder/labca/setup_complete ] && [ ! -e /etc/cron.d/labca ] && ln -sf /opt/labca/cron_d /etc/cron.d/labca || true
    chmod g-w /opt/labca/cron_d
    [ -e /opt/logs/cron.log ] || touch /opt/logs/cron.log
    tail -f -n0 /opt/logs/cron.log &
    service cron start
}

serve_commander() {
    echo "Start serving commander script..."
    tcpserver 0.0.0.0 3030 /opt/labca/commander
}

main() {
    get_fqdn

    setup_boulder_data
    setup_nginx_data
    setup_labca_data

    [ -e /etc/nginx/ssl/labca_cert.pem ] || selfsigned_cert
    renew_near_expiry

    start_cron

    serve_commander
}

main "$@"
