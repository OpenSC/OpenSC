#!/bin/bash

set -ex -o xtrace

brew install automake gengetopt help2man libtool
if [ "$1" == "libressl" ]; then
    brew install libressl
fi

# openSCToken
export PATH="/usr/local/opt/ccache/libexec:$PATH"
git clone https://github.com/frankmorgner/OpenSCToken.git

if [ -n "$KEY_PASSWORD" ]; then
    echo $DEV_ID_APPLICATION | base64 --decode > .github/DeveloperIDApplication.p12
    echo $DEV_ID_INSTALLER | base64 --decode > .github/DeveloperIDInstaller.p12
    .github/add_signing_key.sh;
else
    unset CODE_SIGN_IDENTITY INSTALLER_SIGN_IDENTITY;
fi
