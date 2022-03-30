#!/bin/bash

# get script location directory
SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

tests=(
"run_test_01_state.sh"
"run_test_02_state_postgres.sh"
"run_test_03_hang.sh"
"run_test_04_hangkill.sh"
"run_test_05_snap.sh"
"run_test_06_stacks.sh"
"run_test_10_xz.sh"
)

RED='\033[0;31m'
GR='\033[0;32m'  # green
NC='\033[0m'     # no Color

date_str=$(date "+%Y-%m-%d_%H-%M-%S")
mkdir -p "$SD"/logs

echo "Tests start at $date_str."
echo ""

error_code=0
for _test in "${tests[@]}"; do

  echo "Run test $_test..."
  # run test and write logs
  "$SD"/${_test} &> "$SD"/logs/${date_str}_${_test}.txt
  ec=$?
  # check error code
  if [ "$ec" == "0" ]; then
    echo -e "${GR}$_test is OK$!${NC}"
  else
    echo -e "${RED}$_test is FAILED!{NC}"
    error_code=1
  fi
  echo ""

done

exit $error_code