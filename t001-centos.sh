#!/bin/sh

TEST_NAME="t001"
OS_NAME="centos-7.9"
DB_NAME="pgproee-13.4"
ENV_NAME="pgdd-${TEST_NAME}"

set -e

# Prepare steps
bm cfg add -env ${ENV_NAME} \
           -nodes 1 -backend pgproinfra \
           -os ${OS_NAME} -dbengine ${DB_NAME} \
           -scale default -schema single
bm init third
bm env image -env ${ENV_NAME}
bm env recreate -env ${ENV_NAME}

#
# TODO: 
#  - schedule pg_diagdump.sh
#  - start pgbench
#  - gather results
#    expected: NO OOM, postgres is running, error file is empty
#
bm env play -env ${ENV_NAME} -book t001.yml

# Housekeeping
bm env delete -env ${ENV_NAME}
bm cfg remove -env ${ENV_NAME}

