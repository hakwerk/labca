#!/bin/bash

set -e

get_fqdn() {
    local file_fqdn=""
    if [ -e /admin/data/config.json ]; then
        file_fqdn=$(grep fqdn /admin/data/config.json 2>/dev/null | cut -d ":" -f 2- | tr -d " \",")
    fi
    if [ "$file_fqdn" == "" ]; then
        if [ "$LABCA_FQDN" == "notset" ]; then
            echo "ERROR: environment variable LABCA_FQDN is not set!"
            exit 1
        else
            echo -e "{\n  \"config\": {\n    \"complete\": false\n  },\n  \"labca\": {\n    \"fqdn\": \"$LABCA_FQDN\"\n  },\n  \"version\": \"\"\n}" > /admin/data/config.json
        fi
    elif [ "$LABCA_FQDN" != "notset" ] && [ "$LABCA_FQDN" != "$file_fqdn" ]; then
        echo "WARNING: environment variable LABCA_FQDN ('$LABCA_FQDN') does not match config file. Using '$file_fqdn'..."
        export LABCA_FQDN=$file_fqdn
    fi
}

# TODO: install docker should be done in pre-baked image
install_docker() {
    apt update
    apt install -y apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
    apt install -y docker-ce
}

# TODO: install docker-compose should be done in pre-baked image
install_docker_compose() {
    dockerComposeVersion="v2.5.0"
    local dcver=""
    [ -x /usr/local/bin/docker-compose ] && dcver="`/usr/local/bin/docker-compose --version`"
    local vercmp=${dcver/$dockerComposeVersion/}
    if [ "$dcver" == "" ] || [ "$dcver" == "$vercmp" ]; then
        local v1test=${dcver/version 1./}
        if [ "$dcver" != "$v1test" ] && [ "$dcver" != "" ]; then
            mv /usr/local/bin/docker-compose /usr/local/bin/docker-compose-v1
        fi

        curl -sSL https://github.com/docker/compose/releases/download/$dockerComposeVersion/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
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
            echo "acme-request" | /labca/commander
        fi
    fi
    popd >/dev/null
}

# TODO: install cron should be done in pre-baked image
start_cron() {
    apt update
    apt install -y cron
    [ -e /boulder/labca/setup_complete ] && [ ! -e /etc/cron.d/labca ] && ln -sf /labca/cron_d /etc/cron.d/labca || true
    [ -e /logs/cron.log ] && mv /logs/cron.log "/logs/cron.log-$(date +%y%m%d-%H%M%S)" || true
    touch /logs/cron.log
    tail -f /logs/cron.log &
    service cron start
}

# TODO: install ucspi-tcp should be done in pre-baked image
serve_commander() {
    apt update
    apt install -y ucspi-tcp
    echo "Start serving commander script..."
    tcpserver 0.0.0.0 3030 /labca/commander
}

main() {
    mkdir -p /logs

    get_fqdn

    docker ps >/dev/null || install_docker
    install_docker_compose

    [ -e /etc/nginx/ssl/labca_cert.pem ] || selfsigned_cert
    renew_near_expiry

    start_cron

    serve_commander
}

main "$@"
