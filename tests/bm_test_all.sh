#!/usr/bin/env bash

set -e

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_test.yml"
TEST_NAME="t002"

. "$SD/bm_common.sh"
