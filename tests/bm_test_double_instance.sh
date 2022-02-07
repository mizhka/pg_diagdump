#!/bin/bash

SD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

OS_NAME="centos-7.9"
DB_NAME="pgproee-13.4"
ENV_NAME="pgdd-t003"
PLAYBOOK="$SD/do_double_instance_test.yml"

set -e

# Prepare steps
bm cfg add -env ${ENV_NAME} \
           -nodes 1 -backend pgproinfra \
           -os ${OS_NAME} -dbengine ${DB_NAME} \
           -scale default -schema single
#bm init third
bm env image -env ${ENV_NAME}
bm env recreate -env ${ENV_NAME}

# run tests
bm env play -env ${ENV_NAME} -book ${PLAYBOOK}

# Housekeeping
bm env delete -env ${ENV_NAME}
bm cfg remove -env ${ENV_NAME}

