#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1
TOKENTYPE=${TOKENTYPE:-$TEST_PKCS11_BACKEND}

if [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
fi

source $SOURCE_PATH/tests/common.sh $TOKENTYPE

if [ "${TOKENTYPE}" != "kryoptic" ]; then
    echo "WARNING: ML-KEM is only tested with kryoptic"
    exit 77
fi

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The $TOKENTYPE is not installed. Can not run this test"
    exit 77;
fi

initialize_token

ID=20
for SET in "ML-KEM-512" "ML-KEM-768" "ML-KEM-1024"; do
    echo "======================================================="
    echo "Test $SET"
    echo "======================================================="
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type="$SET" \
        --label="$SET" --id=$ID --usage-encapsulate
    assert $? "Failed to generate $SET key pair"

    $PKCS11_TOOL "${PRIV_ARGS[@]}" --encapsulate -m ML-KEM --id=$ID \
        --output-file=kem.ct --secret-file=kem.ss1
    assert $? "Failed to encapsulate with $SET"

    $PKCS11_TOOL "${PRIV_ARGS[@]}" --decapsulate -m ML-KEM --id=$ID \
        --input-file=kem.ct --output-file=kem.ss2
    assert $? "Failed to decapsulate with $SET"

    cmp kem.ss1 kem.ss2 >/dev/null 2>&1
    assert $? "$SET shared secrets differ"
    [[ $(stat -c %s kem.ss1) == 32 ]]
    assert $? "$SET shared secret is not 32 bytes"

    # A truncated ciphertext must be refused
    head -c 100 kem.ct > kem.short
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --decapsulate -m ML-KEM --id=$ID \
        --input-file=kem.short --output-file=kem.ss3 2>/dev/null
    [[ $? != 0 ]]
    assert $? "$SET decapsulated a truncated ciphertext"

    rm -f kem.ct kem.ss1 kem.ss2 kem.ss3 kem.short
    ID=$((ID + 1))
done

echo "======================================================="
echo "Cleanup"
echo "======================================================="
token_cleanup

exit $ERRORS
