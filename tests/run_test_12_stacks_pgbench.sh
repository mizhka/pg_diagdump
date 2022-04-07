#!/bin/bash

# get script location directory
SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

pg_port=5432
pg_scale=10

psql -U postgres -d postgres -p $pg_port << EOF
    DROP TABLE IF EXISTS pgbench_accounts,pgbench_branches,pgbench_history,pgbench_tellers;
EOF

# init pgbench before test
pgbench -U postgres -d postgres -p $pg_port --scale=$pg_scale -i || {
  echo "pgbench init failed"
  exit 1
}

begin_s=$(date +%s)
delta=0
wait_s=60

# clean out dir
OUT_DIR="$SD/out"
PG_DIAGDUMP="$SD/../pg_diagdump.sh"
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR"/*

# run pgbench to create work load
pgbench -U postgres -d postgres -p $pg_port \
  --scale=$pg_scale --client=10 --jobs=10 --no-vacuum --time=$wait_s -b select-only &> /dev/null &
pgbench_pid=$!

while [ $delta -lt $wait_s ] ; do
#  sleep 1
  exec 5>&1
  file_msg=$( sudo "$PG_DIAGDUMP" -p $pg_port -d "$OUT_DIR" stacks | tee >(cat - >&5) )

  # parse out file name from pg_diagdump.sh
  file=${file_msg#*Generated file: }
  if [ ! -f "$file" ]; then
    echo "results file doesn't exist, file = $file"
    exit 1
  fi

  now_s=$(date +%s)
  delta=$(( $now_s - $begin_s ))
  echo "delta = ${delta}"

done

# kill pgbench by pid
kill $pgbench_pid &> /dev/null

echo "all is done"
