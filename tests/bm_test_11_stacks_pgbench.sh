#!/bin/bash

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_test_11_stacks_pgbench.yml"
TEST_NAME="t011"

. "$SD/bm_common.sh"
