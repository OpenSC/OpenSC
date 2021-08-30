#!/bin/bash

set -ex -o xtrace

if [ -n "$PASS_SECRETS_TAR_ENC" ]; then
    .github/remove_signing_key.sh
fi
