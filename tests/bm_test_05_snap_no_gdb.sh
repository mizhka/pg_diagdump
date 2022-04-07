#!/bin/bash

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_test_05_snap_no_gdb.yml"
TEST_NAME="t005"

. "$SD/bm_common.sh"
