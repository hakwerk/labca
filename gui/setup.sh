#!/bin/bash

set -e

[ -d bin ] || mkdir bin

[ -e bin/labca ] || set -ev
if [ ! -e bin/labca ]; then
    go get github.com/biz/templates
    go get github.com/go-sql-driver/mysql
    go get github.com/dustin/go-humanize
    go get github.com/gorilla/mux
    go get github.com/gorilla/securecookie
    go get github.com/gorilla/sessions
    go get github.com/gorilla/websocket
    go get github.com/nbutton23/zxcvbn-go
    go get github.com/theherk/viper
    go get golang.org/x/crypto/bcrypt

    go build -o bin/labca main.go acme.go certificate.go dashboard.go
fi

bin/labca
