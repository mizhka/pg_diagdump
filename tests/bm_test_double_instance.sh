#!/usr/bin/env bash

set -e

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PLAYBOOK="$SD/do_double_instance_test.yml"
TEST_NAME="t003"

export BM_ENV="pgdd-${TEST_NAME}"
export BM_NODES=1
export BM_OS=centos-7.9
export BM_SCHEMA=single
export BM_SCALE=default
export BM_DBENGINE=pgproee-13.4
export BM_HOST=database0

#bm init third
bm image create
bm env recreate

# run tests
bm ansible play -book ${PLAYBOOK}

# Housekeeping
bm env delete

