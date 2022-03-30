#!/bin/bash

# get script location directory
SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# init pgbench before test
pgbench -U postgres -d postgres -p 5432 -i || {
  echo "pgbench init failed"
  exit 1
}

# run pgbench to create work load
pgbench -U postgres -d postgres -p 5432 --time=600 --client=1 &> /dev/null &
pgbench_pid=$!

# clean out dir
OUT_DIR="$SD/out"
PG_DIAGDUMP="$SD/../pg_diagdump.sh"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR"/*

# run pg_diagdump.sh
exec 5>&1
file_msg=$( sudo "$PG_DIAGDUMP" -x -p 5432 -d "$OUT_DIR" state | tee >(cat - >&5) )

# kill pgbench by pid
kill $pgbench_pid &> /dev/null

# parse out file name from pg_diagdump.sh
file=${file_msg#*Generated file: }
if [ ! -f "$file" ]; then
  echo "results file doesn't exist, file = $file"
  exit 1
fi

comp_count=$(file "$file" | grep -c "XZ compressed data")
if [ "$comp_count" == "0" ]; then
  echo "Error! Archive is not XZ."
  exit 1
fi

# extract archive
mkdir -p "$OUT_DIR/pg_results"
tar -xf "$file" -C "$OUT_DIR/pg_results"

# search for
# exe = '/opt/pgpro/ent-11/bin/postgres'
thread_count=$(grep 'exe =' "$OUT_DIR"/pg_results/diag_*.stacks* | grep postgres | wc -l)
if [ "$thread_count" == "0" ]; then
  echo "Error! Invalid stacks file."
  exit 1
fi

# search for
# postgres 25452/25452  6008.796201:   cycles:
perf_count=$(grep postgres "$OUT_DIR"/pg_results/diag_*.perf | grep "cycles:" | wc -l)
if [ "$perf_count" == "0" ]; then
  echo "Error! Invalid perf file."
  exit 1
fi

# count csv file
csv_count=$(find "$OUT_DIR"/pg_results -name "*.csv" | wc -l)
if [ "$csv_count" == "0" ]; then
  echo "Error! Invalid csv files count."
  exit 1
fi

# get pid of process listening port 5432
pid_5432=$( sudo ss -tlpn | grep 5432 | grep -o -P '(?<=pid\=).*(?=\,fd)' | head -n 1 )
pid_5432_count=$(find "$OUT_DIR"/pg_results -name "*stacks_$pid_5432" | wc -l)
if [ "$pid_5432_count" == "0" ]; then
  echo "Error! Not stack file for port 5432."
  exit 1
fi

echo "Test is OK!"
exit 0
