#!/usr/bin/env bash

set -e

export PS_LABCA="bin/labca"
export PS_BOULDER="bin/boulder"
export PS_BOULDER_COUNT=13
export PS_MYSQL="mysqld"
export PS_SERVICE="tcpserver"

LOOPCOUNT=120

count() {
    local pattern="${1/___/ }"  # escape spaces, e.g. PS_SERVICE="sudo___tcpserver"

    local prefix=""
    case $pattern in
        $PS_LABCA)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -labca-) "
            ;;
        $PS_BOULDER)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -boulder-) "
            ;;
        $PS_MYSQL)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -bmysql-) "
            ;;
        *)
            ;;
    esac

    local res=$(${prefix}ps -eo pid,cmd 2>/dev/null | grep "$pattern" | grep -v grep | wc -l)
    echo $res
}

wait_count() {
    local pattern="$1"
    local count="$2"
    local lc=0

    # Allow more time for the boulder container...
    if [ $count -gt 1 ]; then
        LOOPCOUNT=240
    fi

    local c=$(count $pattern)
    while ( [ $count -gt 0 ] && [ $c -lt $count ] ) || ( [ $count -eq 0 ] && [ $c -gt $count ] ) && [ $lc -lt $LOOPCOUNT ]; do
        let lc=lc+1
        sleep 1
        c=$(count $pattern)
    done
    if ( [ $count -gt 0 ] && [ $c -ge $count ] ) || ( [ $count -eq 0 ] && [ $c -eq $count ] ); then
        return
    fi
    if [ $lc -ge $LOOPCOUNT ]; then
        pattern="${pattern/___/ }"
        if [ $count -gt 1 ]; then
            echo "FAILED to get $count of $pattern (only have $c)"
        else
            echo "FAILED to get $count of $pattern"
        fi
    fi
}

wait_up() {
    wait_count "$1" "${2:-1}"
}

wait_down() {
    wait_count "$1" 0
}

