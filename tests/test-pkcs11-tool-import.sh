#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

source $SOURCE_PATH/tests/common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
card_setup
assert $? "Failed to set up card"

for KEYTYPE in "RSA" "EC"; do
    echo "======================================================="
    echo "Generate and import $KEYTYPE keys"
    echo "======================================================="
    ID="0100"
    OPTS=""
    if [ "$KEYTYPE" == "EC" ]; then
        ID="0200"
        OPTS="-pkeyopt ec_paramgen_curve:P-521"
    fi
    openssl genpkey -out "${KEYTYPE}_private.der" -outform DER -algorithm $KEYTYPE $OPTS
    assert $? "Failed to generate private $KEYTYPE key"
    $PKCS11_TOOL --write-object "${KEYTYPE}_private.der" --id "$ID" --type privkey \
        --label "$KEYTYPE" -p "$PIN" --module "$P11LIB"
    assert $? "Failed to write private $KEYTYPE key"

    openssl pkey -in "${KEYTYPE}_private.der" -out "${KEYTYPE}_public.der" -pubout -inform DER -outform DER
    assert $? "Failed to convert private $KEYTYPE key to public"
    $PKCS11_TOOL --write-object "${KEYTYPE}_public.der" --id "$ID" --type pubkey --label "$KEYTYPE" \
        -p $PIN --module $P11LIB
    assert $? "Failed to write public $KEYTYPE key"
    # certificate import already tested in all other tests

    rm "${KEYTYPE}_private.der" "${KEYTYPE}_public.der"
done

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
