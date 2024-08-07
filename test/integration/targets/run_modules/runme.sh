#!/usr/bin/env bash

set -eux

# test running module directly
python.py library/test.py args.json

TMPFILE=$(shell mktemp -d -p "${OUTPUT_DIR}" 2>/dev/null || mktemp -d -t 'ansible-testing-XXXXXXXXXX' -p "${OUTPUT_DIR}")

# ensure 'command' can use 'raw args'
ansible -m command -a "dd if=/dev/zero of=\"${TMPFILE}\" bs=1K count=1" localhost

# ensure fqcn 'command' can use 'raw args'
ansible -m ansible.legacy.command -a "dd if=/dev/zero of=\"${TMPFILE}\" bs=1K count=1" localhost
