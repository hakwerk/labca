#!/usr/bin/env bash

set -e

export PS_LABCA="bin/labca-gui"
export PS_BOULDER="bin/boulder"
export PS_BOULDER_COUNT=24
export PS_MYSQL="mysqld"
export PS_CONTROL="tcpserver"
export PS_NGINX="nginx:"
export PS_CONSUL="consul"
export PS_PKILINT="pkilint"

LOOPCOUNT=120

count() {
    local pattern="${1/___/ }"  # escape spaces, e.g. PS_CONTROL="sudo___tcpserver"

    local prefix=""
    case $pattern in
        $PS_LABCA)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- labca-gui-) "
            ;;
        $PS_BOULDER)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -boulder-) "
            ;;
        $PS_MYSQL)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -bmysql-) "
            ;;
        $PS_CONTROL)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -control-) "
            ;;
        $PS_CONSUL)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -bconsul-) "
            ;;
        $PS_PKILINT)
            prefix="docker exec $(docker ps --format "{{.Names}}" | grep -- -bpkilint-) "
            ;;
        *)
            ;;
    esac

    local res=$(${prefix}ps -eo pid,cmd 2>/dev/null | grep "$pattern" | grep -v grep | grep -v "go build" | wc -l)
    if [ "$pattern" == "$PS_CONSUL" ]; then
        res=$(${prefix}ps -eo pid,args 2>/dev/null | grep "$pattern" | grep -v grep | wc -l)
    fi
    if [ "$pattern" == "$PS_PKILINT" ]; then
        res=$(${prefix}ls -d /proc/[1-9]* 2>/dev/null | wc -l)
    fi
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

