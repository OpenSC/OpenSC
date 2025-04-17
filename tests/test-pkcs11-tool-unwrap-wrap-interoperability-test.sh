#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

get_priv_args() {
    local target=$1
    case "$target" in
        Kryoptic)
            ARGS=("${PRIV_ARGS_KRYOPTIC[@]}")
            ;;
        Softokn)
            ARGS=("${PRIV_ARGS_SOFTOKN[@]}")
            ;;
        SoftHSM)
            ARGS=("${PRIV_ARGS_SOFTHSM[@]}")
            ;;
        *)
            echo "Unknown target: $target" >&2
            return 1
            ;;
    esac
}

function test_unwrapped_aes_encryption() {
	TARGET=$1
    AES_256_KEY=$2
    KEY_ID=$3
    IV="00000000000000000000000000000000"
    (printf '\xAB%.0s' {1..64};) > aes_plain.data
    get_priv_args "$TARGET"

    echo "Testing unwrapped key with encryption"

    # Encrypt with openssl
    openssl enc -aes-256-cbc -in aes_plain.data -out aes_ciphertext_openssl.data -iv $IV -K $AES_256_KEY
    assert $? "AES CBC OpenSSL encryption failed"

    # Encrypt with pkcs11-tool
    $PKCS11_TOOL "${ARGS[@]}" --encrypt --id $KEY_ID -m AES-CBC-PAD --iv $IV \
            --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data
    assert $? "Fail/pkcs11-tool encrypt"

    # Compare ciphertexts
    cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
    assert $? "AES CBC encrypted ciphertexts do not match"

    rm aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data aes_plain.data
}

source $SOURCE_PATH/tests/help.sh
# Initialize tokens with their custom pkcs11-tool arguments
source $SOURCE_PATH/tests/common.sh softokn
initialize_token
source $SOURCE_PATH/tests/common.sh softhsm
initialize_token
source $SOURCE_PATH/tests/common.sh kryoptic
initialize_token

# Generate AES and RSA keys for wrapping/unwrapping
ID_AES_WRAP="0100"
ID_RSA_WRAP="0200"
ID_RSA_WRAPPED="0201"
ID_RSA_UNWRAPPED="0202"

AES_WRAP_KEY="7070707070707070707070707070707070707070707070707070707070707070"
echo -n $AES_WRAP_KEY | xxd -p -r > aes_wrap.key
IV="00000000000000000000000000000000"

openssl genpkey -out "rsa_private.der" -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:1024
openssl pkey -in "rsa_private.der" -out "rsa_public.der" -pubout -inform DER -outform DER

# import keys
for TARGET in SoftHSM Kryoptic Softokn; do
    get_priv_args "$TARGET"
    # Write AES key for wrapping
    $PKCS11_TOOL "${ARGS[@]}" --write-object aes_wrap.key --id $ID_AES_WRAP \
        --type secrkey --key-type AES:32 --usage-wrap --extractable --label aes-32-wrapping-key
    assert $? "Failed to write AES key to $TARGET"

    # Write RSA private key for unwrapping
    $PKCS11_TOOL "${ARGS[@]}" --write-object rsa_private.der --id $ID_RSA_WRAP \
        --type privkey --usage-wrap --usage-decrypt --label rsa-wrapping-key
    assert $? "Failed to write RSA private key to $TARGET"

    # Write RSA public key  for wrapping
    $PKCS11_TOOL "${ARGS[@]}" --write-object rsa_public.der --id $ID_RSA_WRAP \
        --type pubkey --usage-wrap --usage-decrypt --label rsa-wrapping-key
    assert $? "Failed to write RSA public key to $TARGET"

    # Generate RSA key to be wrapped/unwrapped
    $PKCS11_TOOL "${ARGS[@]}" --keypairgen --key-type rsa:2048 --id $ID_RSA_WRAPPED \
        --usage-decrypt --extractable --label rsa-key
    assert $? "Failed to Generate RSA key"
done

echo "======================================================="
echo " Wrap/Unwrap of secret keys"
echo "======================================================="
# Generate key to be wrapped/unwrapped
ID_AES="0101"
AES_KEY="ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
echo -n $AES_KEY | xxd -p -r > aes.key

for MECH in AES-CBC AES-KEY-WRAP RSA-PKCS; do
    echo "-------------------------------------------------------"
    echo " $MECH Wrap/Unwrap of secret key test"
    echo "-------------------------------------------------------"
    ID_WRAP=$ID_AES_WRAP
    if [ "$MECH" == "RSA-PKCS" ]; then
        ID_WRAP=$ID_RSA_WRAP
    fi
    for WRAPPER in SoftHSM Kryoptic Softokn; do
        for UNWRAPPER in SoftHSM Kryoptic Softokn; do
            if [ "$WRAPPER" == "$UNWRAPPER" ]; then
                continue;
            fi
            if [ "$UNWRAPPER" == "SoftHSM" ] && [ $MECH == "AES-CBC" ]; then
                continue;
            fi
            echo "-------------------------------------------------------"
            echo " $WRAPPER Wrap -> $UNWRAPPER Unwrap"
            echo "-------------------------------------------------------"
            get_priv_args "$WRAPPER"
            # 1. Load key
            $PKCS11_TOOL "${ARGS[@]}" --write-object aes.key --id $ID_AES --type secrkey --key-type AES:32 \
                --usage-decrypt --extractable --label "stored-aes-32"
            assert $? "Failed to write AES key on $WRAPPER"
            # 2. Wrap 
            $PKCS11_TOOL "${ARGS[@]}" --wrap -m $MECH --id $ID_WRAP --iv $IV --application-id $ID_AES \
                --output-file wrapped_key.data
            assert $? "Failed to wrap AES key with $MECH from $WRAPPER"
            
            get_priv_args "$UNWRAPPER"
            #3. Unwrap
            $PKCS11_TOOL "${ARGS[@]}" --unwrap -m $MECH --id $ID_WRAP --iv $IV --application-id $ID_AES \
                --key-type AES: --input-file wrapped_key.data --usage-decrypt --extractable
            assert $? "Failed to unwrap AES key with $MECH by $UNWRAPPER"

            # 4. Test unwrapped key with encryption
            test_unwrapped_aes_encryption $UNWRAPPER $AES_KEY $ID_AES

            # 5. Clean up
            $PKCS11_TOOL "${ARGS[@]}" --delete-object --type secrkey --id $ID_AES
            get_priv_args "$WRAPPER"
            $PKCS11_TOOL "${ARGS[@]}" --delete-object --type secrkey --id $ID_AES
            rm wrapped_key.data
        done
    done
done

echo "======================================================="
echo " Wrap/Unwrap of private keys"
echo "======================================================="

for MECH in AES-CBC-PAD; do
    ID_WRAP=$ID_AES_WRAP

    for WRAPPER in Kryoptic Softokn; do
        for UNWRAPPER in Kryoptic Softokn; do
            if [ "$WRAPPER" == "$UNWRAPPER" ]; then
                continue;
            fi
            if { [[ "$MECH" == "AES-CBC-PAD" ]] && ([[ "$WRAPPER" == "SoftHSM" ]] || [[ "$UNWRAPPER" == "SoftHSM" ]]); } || \
            { [[ "$MECH" == "AES-KEY-WRAP-PAD" ]] && ([[ "$WRAPPER" == "Kryoptic" ]] || [[ "$UNWRAPPER" == "Kryoptic" ]]); }; then
                continue
            fi
            echo "-------------------------------------------------------"
            echo " $MECH: $WRAPPER Wrap -> $UNWRAPPER Unwrap"
            echo "-------------------------------------------------------"
            # Wrap
            get_priv_args "$WRAPPER"
            $PKCS11_TOOL "${ARGS[@]}" --wrap -m $MECH --id $ID_AES_WRAP --iv $IV \
                --application-id $ID_RSA_WRAPPED --output-file rsa_wrapped_key.data
            assert $? "Failed to wrap RSA key by $WRAPPER"
            # Unwrap
            get_priv_args "$UNWRAPPER"
            $PKCS11_TOOL "${ARGS[@]}" --unwrap -m $MECH --id $ID_AES_WRAP --iv $IV \
                --application-id $ID_RSA_UNWRAPPED --key-type RSA:2048 --input-file rsa_wrapped_key.data
            assert $? "Failed to unwrap RSA key with $MECH by $UNWRAPPER"
            rm rsa_wrapped_key.data

            # Remove unwrapped RSA key
            $PKCS11_TOOL "${PRIV_ARGS[@]}" --delete-object --type privkey --id $ID_RSA_UNWRAPPED
        done
    done
done


echo "======================================================="
echo "Cleanup"
echo "======================================================="
rm aes_wrap.key rsa_private.der rsa_public.der aes.key

exit $ERRORS
