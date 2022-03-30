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
file_msg=$( sudo "$PG_DIAGDUMP" -p 5432 -d "$OUT_DIR" snap | tee >(cat - >&5) )

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
tar -xf "$file" -C "$OUT_DIR/pg_results"

# count csv file
csv_count=$(find "$OUT_DIR"/pg_results -name "*.csv" | wc -l)
if [ "$csv_count" == "0" ]; then
  echo "Error! Invalid csv files count."
  exit 1
fi

select_count=$(grep -c select "$OUT_DIR"/pg_results/*)
if [ "$select_count" == "0" ]; then
  echo "Error! No one select found."
  exit 1
fi

echo "Test is OK!"
exit 0
