#!/bin/bash

# get script location directory
SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# init pgbench before test
pgbench -U postgres -d postgres -i || {
  echo "pgbench init failed"
  exit 1
}

# run pgbench to create work load
pgbench -U postgres -d postgres --time=600 --client=1 &> /dev/null &
pgbench_pid=$!

# clean out dir
OUT_DIR="$SD/out"
PG_DIAGDUMP="$SD/../pg_diagdump.sh"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR"/*

# run pg_diagdump.sh
exec 5>&1
file_msg=$( sudo "$PG_DIAGDUMP" -p 5432 -d "$OUT_DIR" stacks | tee >(cat - >&5) )

# kill pgbench by pid
kill $pgbench_pid &> /dev/null

# parse out file name from pg_diagdump.sh
file=${file_msg#*Generated file: }
if [ ! -f "$file" ]; then
  echo "results file doesn't exist, file = $file"
  exit 1
fi

# extract archive
mkdir -p "$OUT_DIR/pg_results"
tar -xzf "$file" -C "$OUT_DIR/pg_results"

# search for
# exe = '/opt/pgpro/ent-11/bin/postgres'
thread_count=$(grep 'exe =' "$OUT_DIR"/pg_results/diag_*.stacks* | grep postgres | wc -l)
if [ "$thread_count" == "0" ]; then
  echo "Error! Invalid stacks file."
  exit 1
fi

echo "Test is OK!"
exit 0
