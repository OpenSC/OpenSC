#!/bin/bash
# command line parameter overrides engine to test, opensc or pkcs11
# Organization name embedded below (e.g, MTPPI) must match ca key for ca signing to work
ENGINE=pkcs11

if [[ -ne $1 ]] ;
then
 ENGINE=$1;
fi;

if [[ $ENGINE == "pkcs11" ]];
then 
POSTCMD="-pre MODULE_PATH:../pkcs11/.libs/opensc-pkcs11.so" ;
echo;
fi;

# self-signed certificate has a locking problem, don't try yet....
openssl << EOT
engine dynamic -vvvv -pre SO_PATH:.libs/engine_${ENGINE}.so -pre ID:${ENGINE} -pre NO_VCHECK:1 -pre LIST_ADD:1 -pre LOAD ${POSTCMD}
req -engine ${ENGINE} -new -x509 -key 45 -keyform engine -out /tmp/selfcert.crt -text
US
Maryland
Bethesda
MTPPI
Organizational Unit
Common Name
email@example.com
EOT
if [[ $? -ne 0 ]] ;
then
 echo "Error generating self-signed cert" 
 exit 1;
fi;

#generate certificate request
# note that the test_engine.openssl has values for certificate info. 
# company name needs to match ca certificate used to sign (below).
openssl << EOT
engine dynamic -vvvv -pre SO_PATH:.libs/engine_${ENGINE}.so -pre ID:${ENGINE} -pre NO_VCHECK:1 -pre LIST_ADD:1 -pre LOAD ${POSTCMD}
req -engine ${ENGINE} -md5 -new -key 45 -keyform engine -out /tmp/cert.md5.crq -text
US
Maryland
Bethesda
MTPPI
Organizational Unit
Common Name
email@example.com


EOT
if [[ $? -ne 0 ]] ;
then
 echo "Error generating cert request" 
 exit 1;
fi;

# sign certificate, assumes ca configured
openssl ca -in /tmp/cert.md5.crq -out /tmp/test.crt || (echo "Error signing certificate" && exit 1)

