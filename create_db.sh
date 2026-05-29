#!/usr/bin/env bash

set -e -u

function exit_err() {
  if [ ! -z "$1" ]
  then
    echo $1 > /dev/stderr
  fi
  exit 1
}

dbconn="-u root -h boulder-mysql --port 3306"

if [ -d /var/lib/mysql/boulder_sa ]; then
    echo "Database boulder_sa already exists, so not creating it"

    # Always update the user grants just to be safe...
    file="/opt/boulder/sa/db/02-users.sql"
    echo "Executing script ${file}..."
    mysql ${dbconn} < ${file} || exit_err "failed to run script ${file}"

else
    echo "Creating database boulder_sa..."

    if ! mysql ${dbconn} -e "select 1" >/dev/null 2>&1; then
        exit_err "unable to connect to boulder-mysql:3306"
    fi

    mysql ${dbconn} -e "SET GLOBAL binlog_format = 'MIXED';"
    mysql ${dbconn} -e "SET GLOBAL max_connections = 500;"

    for file in `ls -1 /opt/boulder/sa/db/*.sql`; do
        echo "Executing script ${file}..."
        mysql ${dbconn} < ${file} || exit_err "failed to run script ${file}"
    done
fi

