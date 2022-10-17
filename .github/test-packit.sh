#!/bin/bash

# Install build requirements
REQUIREMENTS=$(sed -n -e '/^BuildRequires*/p' packaging/opensc.spec | sed 's/[^ ]* //')
sudo dnf install -y ${REQUIREMENTS}

# Run packit
packit --debug build locally
