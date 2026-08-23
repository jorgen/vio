#!/bin/bash
# The entry point the QUIC Interop Runner calls, in both roles.
#
# Everything the endpoint needs arrives in the environment, so both branches
# run the same binary; what differs is that a client must not start before the
# network simulator between it and the server is up.
set -e

# Provided by the endpoint base image: brings up the interfaces and routes that
# put the simulator on the path. Absent when the image is run on an ordinary
# docker network, which is how it is tested locally.
if [ -f /setup.sh ]; then
    # shellcheck disable=SC1091
    source /setup.sh
fi

echo "vio interop endpoint: role=$ROLE testcase=$TESTCASE"

if [ "$ROLE" == "client" ]; then
    if [ -f /wait-for-it.sh ]; then
        /wait-for-it.sh sim:57832 -s -t 30
    fi
    echo "requests: $REQUESTS"
fi

# The binary decides what it supports and exits 127 when the answer is no,
# which the runner reads as unsupported rather than failed. Its status is this
# script's status.
exec ./vio_interop_endpoint
