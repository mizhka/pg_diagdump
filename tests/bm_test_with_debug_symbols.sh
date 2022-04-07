#!/bin/bash

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_test_with_debug_symbols.yml"
TEST_NAME="t013"

. "$SD/bm_common.sh"
