/*
 * PKCS#11 RSA-PSS parameter validation, shared by operation initialization
 * and hardware-independent unit tests.
 *
 * Extracted from framework-pkcs15.c:
 * Copyright (C) 2002 Timo Teräs <timo.teras@iki.fi>
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef OPENSC_PKCS11_PSS_PARAMS_H
#define OPENSC_PKCS11_PSS_PARAMS_H

#include "pkcs11.h"

/* Validate the mechanism-level parameters before any signing operation.
 * Salt-length bounds depend on the key and padding implementation.
 */
static inline CK_RV
sc_pkcs11_validate_pss_params(CK_MECHANISM_PTR pMechanism)
{
	const CK_RSA_PKCS_PSS_PARAMS *pss_params;
	unsigned int expected_hash = 0, i;
	const unsigned int hashes[5] = {CKM_SHA_1, CKM_SHA256,
			CKM_SHA384, CKM_SHA512, CKM_SHA224};

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (!pMechanism->pParameter ||
			pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
		return CKR_MECHANISM_PARAM_INVALID;

	pss_params = (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
	switch (pss_params->mgf) {
	case CKG_MGF1_SHA1:
	case CKG_MGF1_SHA224:
	case CKG_MGF1_SHA256:
	case CKG_MGF1_SHA384:
	case CKG_MGF1_SHA512:
		break;
	default:
		return CKR_MECHANISM_PARAM_INVALID;
	}

	/* CKM_RSA_PKCS_PSS accepts any supported hash. Combined mechanisms
	 * require the hash declared in the mechanism.
	 */
	if (pMechanism->mechanism == CKM_SHA1_RSA_PKCS_PSS) {
		expected_hash = CKM_SHA_1;
	} else if (pMechanism->mechanism == CKM_SHA224_RSA_PKCS_PSS) {
		expected_hash = CKM_SHA224;
	} else if (pMechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS) {
		expected_hash = CKM_SHA256;
	} else if (pMechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS) {
		expected_hash = CKM_SHA384;
	} else if (pMechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS) {
		expected_hash = CKM_SHA512;
	} else if (pMechanism->mechanism == CKM_RSA_PKCS_PSS) {
		for (i = 0; i < 5; ++i) {
			if (hashes[i] == pss_params->hashAlg) {
				expected_hash = hashes[i];
			}
		}
	}

	if (expected_hash == 0 || expected_hash != pss_params->hashAlg)
		return CKR_MECHANISM_PARAM_INVALID;

	return CKR_OK;
}

#endif /* OPENSC_PKCS11_PSS_PARAMS_H */
