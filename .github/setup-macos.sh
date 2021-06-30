#!/bin/bash

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

# TODO make the encrypted key working in github
if [ "$GITHUB_EVENT_NAME" == "pull_request" -a -n "$encrypted_3b9f0b9d36d1_key" ]; then
    openssl aes-256-cbc -K $encrypted_3b9f0b9d36d1_key -iv $encrypted_3b9f0b9d36d1_iv -in .github/secrets.tar.enc -out .github/secrets.tar -d;
    .github/add_signing_key.sh;
else
    unset CODE_SIGN_IDENTITY INSTALLER_SIGN_IDENTITY;
fi
