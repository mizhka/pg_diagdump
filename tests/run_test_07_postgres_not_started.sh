#!/bin/bash

# postgres is not running

# get script location directory
SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# clean out dir
OUT_DIR="$SD/out"
PG_DIAGDUMP="$SD/../pg_diagdump.sh"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR"/*

# run pg_diagdump.sh
exec 5>&1
file_msg=$( sudo "$PG_DIAGDUMP" -d "$OUT_DIR" state )

msg_count=$(echo $file_msg | grep "No one PostgreSQL instance is found" | wc -l)
if [ "$msg_count" == "0" ]; then
  echo "Error! Invalid error message."
  exit 1
fi

echo "Test is OK!"
exit 0
