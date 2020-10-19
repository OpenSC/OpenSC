#!/bin/sh

set -ex -o xtrace

pushd .github/
tar xvf secrets.tar
KEY_CHAIN=mac-build.keychain

# Create the keychain with a password
security create-keychain -p travis $KEY_CHAIN

# Make the custom keychain default, so xcodebuild will use it for signing
security default-keychain -s $KEY_CHAIN

# Unlock the keychain for one hour
security unlock-keychain -p travis $KEY_CHAIN
security set-keychain-settings -t 3600 -u $KEY_CHAIN

# Add certificates to keychain and allow codesign to access them
curl -L https://developer.apple.com/certificationauthority/AppleWWDRCA.cer > AppleWWDRCA.cer
security import AppleWWDRCA.cer \
    -k ~/Library/Keychains/$KEY_CHAIN \
    -T /usr/bin/codesign -T /usr/bin/productsign
security import DeveloperIDApplication.cer \
    -k ~/Library/Keychains/$KEY_CHAIN \
    -T /usr/bin/codesign -T /usr/bin/productsign
security import DeveloperIDInstaller.cer \
    -k ~/Library/Keychains/$KEY_CHAIN \
    -T /usr/bin/codesign -T /usr/bin/productsign
security import key.p12 \
    -k ~/Library/Keychains/$KEY_CHAIN -P $KEY_PASSWORD \
    -T /usr/bin/codesign -T /usr/bin/productsign
security unlock-keychain -p travis $KEY_CHAIN

# https://docs.travis-ci.com/user/common-build-problems/#mac-macos-sierra-1012-code-signing-errors
security set-key-partition-list -S apple-tool:,apple: -s -k travis $KEY_CHAIN
popd
