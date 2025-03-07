#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1

if [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
fi

source $SOURCE_PATH/tests/common.sh $TOKENTYPE

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The $TOKENTYPE is not installed. Can not run this test"
    exit 77;
fi
card_setup
assert $? "Failed to set up card"

# To add Ed25519 will require OpenSSL 3.2 and use of genpkey -outpubkey
# which will also work for other keys, and will not require openssl pkey 

for KEYTYPE in "RSA" "EC"; do
    echo "======================================================="
    echo "Generate and import $KEYTYPE keys"
    echo "======================================================="
    ID="0100"
    OPTS="-pkeyopt rsa_keygen_bits:2048"
    if [ "$KEYTYPE" == "EC" ]; then
        ID="0200"
        OPTS="-pkeyopt ec_paramgen_curve:P-256"
    fi
    openssl genpkey -out "${KEYTYPE}_private.der" -outform DER -algorithm $KEYTYPE $OPTS

    assert $? "Failed to generate private $KEYTYPE key"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object "${KEYTYPE}_private.der" --id "$ID" \
        --type privkey --label "$KEYTYPE"
    assert $? "Failed to write private $KEYTYPE key"
    echo "Private key written"

    openssl pkey -in "${KEYTYPE}_private.der" -out "${KEYTYPE}_public.der" -pubout -inform DER -outform DER
    assert $? "Failed to convert private $KEYTYPE key to public"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object "${KEYTYPE}_public.der" --id "$ID" --type pubkey --label "$KEYTYPE"
    assert $? "Failed to write public $KEYTYPE key"
    echo "Public key written"

    rm "${KEYTYPE}_private.der" "${KEYTYPE}_public.der"
done

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
