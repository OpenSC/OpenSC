#!/bin/bash

set -ex -o xtrace

if [ "$GITHUB_EVENT_NAME" != "pull_request" -a -n "$PASS_SECRETS_TAR_ENC" ]; then
    .github/remove_signing_key.sh
fi
