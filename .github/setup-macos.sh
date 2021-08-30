#!/bin/bash

set -ex -o xtrace

brew install automake

# gengetopt
curl https://ftp.gnu.org/gnu/gengetopt/gengetopt-2.23.tar.xz -L --output gengetopt-2.23.tar.xz
tar xfj gengetopt-2.23.tar.xz
pushd gengetopt-2.23
./configure && make
sudo make install
popd

# help2man
curl https://ftp.gnu.org/gnu/help2man/help2man-1.47.16.tar.xz -L --output help2man-1.47.16.tar.xz
tar xjf help2man-1.47.16.tar.xz
pushd help2man-1.47.16
./configure && make
sudo make install
popd

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
