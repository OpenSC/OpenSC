#!/bin/bash

set -ex -o xtrace

# Install build requirements
REQUIREMENTS=$(sed -n -e '/^BuildRequires*/p' packaging/opensc.spec | sed 's/[^ ]* //')
dnf install -y ${REQUIREMENTS}

# Run packit
packit --debug build locally
