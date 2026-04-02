#!/bin/bash

set -ex -o xtrace

if [ -n "$KEY_PASSWORD" ]; then
    .github/remove_signing_key.sh
fi
