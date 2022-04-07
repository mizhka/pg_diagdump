#!/bin/bash

export BM_ENV="pgdd-${TEST_NAME}"
export BM_NODES=1
export BM_OS=centos-7.9
export BM_SCHEMA=single
export BM_SCALE=default
export BM_DBENGINE=pgproee-13.4
export BM_HOST=database0
export BM_BACKEND=pgproinfra

#bm init third
bm image create
bm env recreate

# run tests
bm ansible play -book ${PLAYBOOK}

# Housekeeping
bm env delete > /dev/null 2>&1
