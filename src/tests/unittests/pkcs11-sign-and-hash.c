/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Unit tests verifying that combined sign+hash mechanisms (e.g. CKM_ECDSA_SHA256)
 * fall back to software hashing when the key's algorithm references (algo_refs)
 * restrict hardware capabilities to raw signing (e.g. CKM_ECDSA).
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "pkcs11/mechanism.c"
#include "torture.h"

struct sc_context *context = NULL;

CK_RV
session_start_operation(struct sc_pkcs11_session *session, int operation_type,
		sc_pkcs11_mechanism_type_t *type, struct sc_pkcs11_operation **operation)
{
	(void)session;
	(void)operation_type;
	(void)type;
	(void)operation;
	return CKR_GENERAL_ERROR;
}

CK_RV
session_get_operation(struct sc_pkcs11_session *session, int operation_type,
		struct sc_pkcs11_operation **operation)
{
	(void)session;
	(void)operation_type;
	(void)operation;
	return CKR_GENERAL_ERROR;
}

CK_RV
session_stop_operation(struct sc_pkcs11_session *session, int operation_type)
{
	(void)session;
	(void)operation_type;
	return CKR_GENERAL_ERROR;
}

#ifdef ENABLE_OPENSSL
void
sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *card)
{
	(void)card;
}

CK_RV
sc_pkcs11_verify_data(const CK_BYTE_PTR pubkey, CK_ULONG pubkey_len,
		const CK_BYTE_PTR pubkey_params, CK_ULONG pubkey_params_len,
		CK_MECHANISM_PTR mech, sc_pkcs11_operation_t *md,
		CK_BYTE_PTR inp, CK_ULONG inp_len, CK_BYTE_PTR signat, CK_ULONG signat_len)
{
	(void)pubkey;
	(void)pubkey_len;
	(void)pubkey_params;
	(void)pubkey_params_len;
	(void)mech;
	(void)md;
	(void)inp;
	(void)inp_len;
	(void)signat;
	(void)signat_len;
	return CKR_GENERAL_ERROR;
}
#endif

/* Mock hashing implementation */
static CK_RV
mock_md_init(sc_pkcs11_operation_t *operation)
{
	(void)operation;
	return CKR_OK;
}

static sc_pkcs11_mechanism_type_t mock_hash_type = {
	.obj_size = sizeof(sc_pkcs11_operation_t),
	.md_init = mock_md_init,
};

static struct hash_signature_info mock_ecdsa_sha256_info = {
	.mech = CKM_ECDSA_SHA256,
	.hash_mech = CKM_SHA256,
	.sign_mech = CKM_ECDSA,
	.hash_type = &mock_hash_type,
};

static sc_pkcs11_mechanism_type_t mock_combined_type = {
	.mech = CKM_ECDSA_SHA256,
	.mech_data = &mock_ecdsa_sha256_info,
	.obj_size = sizeof(sc_pkcs11_operation_t),
	.release = sc_pkcs11_operation_release,
};

static sc_pkcs11_mechanism_type_t mock_raw_type = {
	.mech = CKM_ECDSA,
	.mech_data = NULL,
	.obj_size = sizeof(sc_pkcs11_operation_t),
	.release = sc_pkcs11_operation_release,
};

/* Key supports only CKM_ECDSA (raw ECDSA) */
static CK_RV
mock_can_do_raw_ecdsa_only(struct sc_pkcs11_session *session, void *key,
		CK_MECHANISM_TYPE mech_type, unsigned int flags)
{
	(void)session;
	(void)key;
	(void)flags;
	if (mech_type == CKM_ECDSA)
		return CKR_OK;
	return CKR_MECHANISM_INVALID;
}

/* Key supports both CKM_ECDSA and CKM_ECDSA_SHA256 in hardware */
static CK_RV
mock_can_do_both(struct sc_pkcs11_session *session, void *key,
		CK_MECHANISM_TYPE mech_type, unsigned int flags)
{
	(void)session;
	(void)key;
	(void)flags;
	if (mech_type == CKM_ECDSA || mech_type == CKM_ECDSA_SHA256)
		return CKR_OK;
	return CKR_MECHANISM_INVALID;
}

/* Key does not support CKM_ECDSA at all */
static CK_RV
mock_can_do_none(struct sc_pkcs11_session *session, void *key,
		CK_MECHANISM_TYPE mech_type, unsigned int flags)
{
	(void)session;
	(void)key;
	(void)flags;
	(void)mech_type;
	return CKR_MECHANISM_INVALID;
}

/*
 * When the key only supports raw CKM_ECDSA in hardware, CKM_ECDSA_SHA256
 * must succeed by falling back to software hashing.
 */
static void
test_sign_init_fallback_to_software_hash(void **state)
{
	struct sc_pkcs11_object_ops ops = { .can_do = mock_can_do_raw_ecdsa_only };
	struct sc_pkcs11_object key = { .ops = &ops };
	sc_pkcs11_operation_t op = { .type = &mock_combined_type };
	struct operation_data *data;
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_signature_init(&op, &key);
	assert_int_equal(rc, CKR_OK);
	data = (struct operation_data *)op.priv_data;
	assert_non_null(data);
	assert_non_null(data->md); /* software hashing initialized */
	sc_pkcs11_operation_release(&op);
}

/*
 * When the key supports CKM_ECDSA_SHA256 directly on-card,
 * software hashing must not be initialized (can_do_it = 1).
 */
static void
test_sign_init_on_card_hashing(void **state)
{
	struct sc_pkcs11_object_ops ops = { .can_do = mock_can_do_both };
	struct sc_pkcs11_object key = { .ops = &ops };
	sc_pkcs11_operation_t op = { .type = &mock_combined_type };
	struct operation_data *data;
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_signature_init(&op, &key);
	assert_int_equal(rc, CKR_OK);
	data = (struct operation_data *)op.priv_data;
	assert_non_null(data);
	assert_null(data->md); /* on-card hashing */
	sc_pkcs11_operation_release(&op);
}

/*
 * When the key supports neither the combined mechanism nor the base mechanism,
 * signature_init must fail with CKR_MECHANISM_INVALID.
 */
static void
test_sign_init_base_mech_unsupported(void **state)
{
	struct sc_pkcs11_object_ops ops = { .can_do = mock_can_do_none };
	struct sc_pkcs11_object key = { .ops = &ops };
	sc_pkcs11_operation_t op = { .type = &mock_combined_type };
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_signature_init(&op, &key);
	assert_int_equal(rc, CKR_MECHANISM_INVALID);
}

/*
 * When the mechanism is raw CKM_ECDSA and key supports CKM_ECDSA,
 * signature_init succeeds without software hashing.
 */
static void
test_sign_init_raw_mechanism_supported(void **state)
{
	struct sc_pkcs11_object_ops ops = { .can_do = mock_can_do_raw_ecdsa_only };
	struct sc_pkcs11_object key = { .ops = &ops };
	sc_pkcs11_operation_t op = { .type = &mock_raw_type };
	struct operation_data *data;
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_signature_init(&op, &key);
	assert_int_equal(rc, CKR_OK);
	data = (struct operation_data *)op.priv_data;
	assert_non_null(data);
	assert_null(data->md);
	sc_pkcs11_operation_release(&op);
}

/*
 * When the mechanism is raw CKM_ECDSA but key does not support CKM_ECDSA,
 * signature_init fails with CKR_MECHANISM_INVALID.
 */
static void
test_sign_init_raw_mechanism_unsupported(void **state)
{
	struct sc_pkcs11_object_ops ops = { .can_do = mock_can_do_none };
	struct sc_pkcs11_object key = { .ops = &ops };
	sc_pkcs11_operation_t op = { .type = &mock_raw_type };
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_signature_init(&op, &key);
	assert_int_equal(rc, CKR_MECHANISM_INVALID);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sign_init_fallback_to_software_hash),
		cmocka_unit_test(test_sign_init_on_card_hashing),
		cmocka_unit_test(test_sign_init_base_mech_unsupported),
		cmocka_unit_test(test_sign_init_raw_mechanism_supported),
		cmocka_unit_test(test_sign_init_raw_mechanism_unsupported),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
