#!/bin/bash

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_test_12_stacks_pgbench.yml"
TEST_NAME="t012"

. "$SD/bm_common.sh"
