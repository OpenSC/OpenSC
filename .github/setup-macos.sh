#!/bin/bash

set -ex -o xtrace

brew install automake gengetopt help2man pkgconfig libtool

# openSCToken
export PATH="/usr/local/opt/ccache/libexec:$PATH"
git clone https://github.com/frankmorgner/OpenSCToken.git
sudo rm -rf /Library/Developer/CommandLineTools;

if [ -n "$PASS_SECRETS_TAR_ENC" ]; then
    gpg --quiet --batch --yes --decrypt --passphrase="$PASS_SECRETS_TAR_ENC" --output .github/secrets.tar .github/secrets.tar.gpg
    .github/add_signing_key.sh;
else
    unset CODE_SIGN_IDENTITY INSTALLER_SIGN_IDENTITY;
fi
