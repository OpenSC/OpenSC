/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Operation initialization must reject invalid RSA-PSS parameters before
 * accessing a card. These tests need no PKCS#11 session or hardware.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "pkcs11/pkcs11-pss-params.h"
#include "torture.h"

static const struct {
	CK_MECHANISM_TYPE hash;
	CK_MECHANISM_TYPE mechanism;
	CK_ULONG length;
} hashes[] = {
		{CKM_SHA_1,  CKM_SHA1_RSA_PKCS_PSS,   20},
		{CKM_SHA224, CKM_SHA224_RSA_PKCS_PSS, 28},
		{CKM_SHA256, CKM_SHA256_RSA_PKCS_PSS, 32},
		{CKM_SHA384, CKM_SHA384_RSA_PKCS_PSS, 48},
		{CKM_SHA512, CKM_SHA512_RSA_PKCS_PSS, 64},
};

static void
reject_unknown_hash_including_zero(void **state)
{
	const CK_MECHANISM_TYPE invalid[] = {
			0, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_VENDOR_DEFINED};
	CK_RSA_PKCS_PSS_PARAMS params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_PSS, &params, sizeof(params)};
	CK_RV rc;
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		params.hashAlg = invalid[i];
		rc = sc_pkcs11_validate_pss_params(&mechanism);
		assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	}
}

static void
accept_supported_hash_and_mgf_combinations(void **state)
{
	const CK_RSA_PKCS_MGF_TYPE mgfs[] = {
			CKG_MGF1_SHA1, CKG_MGF1_SHA224, CKG_MGF1_SHA256,
			CKG_MGF1_SHA384, CKG_MGF1_SHA512};
	CK_RSA_PKCS_PSS_PARAMS params;
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_PSS, &params, sizeof(params)};
	CK_RV rc;
	size_t i, j;

	(void)state;
	/* PKCS#11 permits an MGF digest distinct from the message digest. */
	for (i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
		params.hashAlg = hashes[i].hash;
		params.sLen = hashes[i].length;
		for (j = 0; j < sizeof(mgfs) / sizeof(mgfs[0]); j++) {
			params.mgf = mgfs[j];
			mechanism.mechanism = CKM_RSA_PKCS_PSS;
			rc = sc_pkcs11_validate_pss_params(&mechanism);
			assert_int_equal(rc, CKR_OK);
			mechanism.mechanism = hashes[i].mechanism;
			rc = sc_pkcs11_validate_pss_params(&mechanism);
			assert_int_equal(rc, CKR_OK);
		}
	}
}

static void
reject_combined_mechanism_hash_mismatch(void **state)
{
	CK_RSA_PKCS_PSS_PARAMS params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS_PSS, &params, sizeof(params)};
	CK_RV rc;
	size_t i, j;

	(void)state;
	for (i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
		mechanism.mechanism = hashes[i].mechanism;
		for (j = 0; j < sizeof(hashes) / sizeof(hashes[0]); j++) {
			params.hashAlg = hashes[j].hash;
			rc = sc_pkcs11_validate_pss_params(&mechanism);
			assert_int_equal(rc, i == j ? CKR_OK : CKR_MECHANISM_PARAM_INVALID);
		}
		params.hashAlg = 0;
		rc = sc_pkcs11_validate_pss_params(&mechanism);
		assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	}
}

static void
reject_invalid_parameter_storage(void **state)
{
	CK_RSA_PKCS_PSS_PARAMS params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_PSS, NULL, sizeof(params)};
	CK_RV rc;

	(void)state;
	rc = sc_pkcs11_validate_pss_params(NULL_PTR);
	assert_int_equal(rc, CKR_ARGUMENTS_BAD);
	rc = sc_pkcs11_validate_pss_params(&mechanism);
	assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	mechanism.pParameter = &params;
	mechanism.ulParameterLen = 0;
	rc = sc_pkcs11_validate_pss_params(&mechanism);
	assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	mechanism.ulParameterLen = sizeof(params) - 1;
	rc = sc_pkcs11_validate_pss_params(&mechanism);
	assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	mechanism.ulParameterLen = sizeof(params) + 1;
	rc = sc_pkcs11_validate_pss_params(&mechanism);
	assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
}

static void
reject_invalid_mgf(void **state)
{
	const CK_RSA_PKCS_MGF_TYPE invalid[] = {0, CKG_MGF1_SHA3_224, ~0UL};
	CK_RSA_PKCS_PSS_PARAMS params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_PSS, &params, sizeof(params)};
	CK_RV rc;
	size_t i;

	(void)state;
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		params.mgf = invalid[i];
		rc = sc_pkcs11_validate_pss_params(&mechanism);
		assert_int_equal(rc, CKR_MECHANISM_PARAM_INVALID);
	}
}

static void
accept_non_default_salt_lengths(void **state)
{
	const CK_ULONG lengths[] = {0, 1, 20, 32, 222};
	CK_RSA_PKCS_PSS_PARAMS params = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_PSS, &params, sizeof(params)};
	CK_RV rc;
	size_t i;

	(void)state;
	/* Parameter initialization must not require salt length == digest
	 * length: each of these lengths can be encoded with a 2048-bit key.
	 */
	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		params.sLen = lengths[i];
		rc = sc_pkcs11_validate_pss_params(&mechanism);
		assert_int_equal(rc, CKR_OK);
	}
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(reject_unknown_hash_including_zero),
			cmocka_unit_test(accept_supported_hash_and_mgf_combinations),
			cmocka_unit_test(reject_combined_mechanism_hash_mismatch),
			cmocka_unit_test(reject_invalid_parameter_storage),
			cmocka_unit_test(reject_invalid_mgf),
			cmocka_unit_test(accept_non_default_salt_lengths),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
