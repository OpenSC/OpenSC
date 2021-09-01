#!/bin/bash

set -ex -o xtrace

# Select the right java
sudo update-java-alternatives -s java-1.8.0-openjdk-amd64
sudo update-alternatives --get-selections | grep ^java
export PATH="/usr/lib/jvm/java-8-openjdk-amd64/bin/:$PATH"
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/
env | grep -i openjdk

# VSmartcard
./.github/setup-vsmartcard.sh

# Javacard SDKs
if [ ! -d "oracle_javacard_sdks" ]; then
	git clone https://github.com/martinpaljak/oracle_javacard_sdks.git
fi
export JC_HOME=$PWD/oracle_javacard_sdks/jc222_kit
export JC_CLASSIC_HOME=$PWD/oracle_javacard_sdks/jc305u3_kit

# jCardSim
if [ ! -d "jcardsim" ]; then
	git clone https://github.com/Jakuje/jcardsim.git
fi
pushd jcardsim
env | grep -i openjdk
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/
mvn initialize && mvn clean install
popd
