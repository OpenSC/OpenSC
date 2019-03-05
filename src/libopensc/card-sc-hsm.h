/*
 * sc-hsm.h
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef SC_HSM_H_
#define SC_HSM_H_

#include "pkcs15.h"
#include "internal.h"

#define MAX_EXT_APDU_LENGTH 1014

#define PRKD_PREFIX				0xC4		/* Hi byte in file identifier for PKCS#15 PRKD objects */
#define CD_PREFIX				0xC8		/* Hi byte in file identifier for PKCS#15 CD objects */
#define DCOD_PREFIX				0xC9		/* Hi byte in file identifier for PKCS#15 DCOD objects */
#define CA_CERTIFICATE_PREFIX	0xCA		/* Hi byte in file identifier for CA certificates */
#define KEY_PREFIX				0xCC		/* Hi byte in file identifier for key objects */
#define PROT_DATA_PREFIX		0xCD		/* Hi byte in file identifier for PIN protected data objects */
#define EE_CERTIFICATE_PREFIX	0xCE		/* Hi byte in file identifier for EE certificates */
#define DATA_PREFIX				0xCF		/* Hi byte in file identifier for readable data objects */

#define ALGO_RSA_RAW			0x20		/* RSA signature with external padding */
#define ALGO_RSA_DECRYPT		0x21		/* RSA decrypt */
#define ALGO_RSA_PKCS1			0x30		/* RSA signature with DigestInfo input and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA1		0x31		/* RSA signature with SHA-1 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA256	0x33		/* RSA signature with SHA-256 hash and PKCS#1 V1.5 padding */

#define ALGO_RSA_PSS			0x40		/* RSA signature with external hash and PKCS#1 PSS padding*/
#define ALGO_RSA_PSS_SHA1		0x41		/* RSA signature with SHA-1 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA256		0x43		/* RSA signature with SHA-256 hash and PKCS#1 PSS padding */

#define ALGO_EC_RAW				0x70		/* ECDSA signature with hash input */
#define ALGO_EC_SHA1			0x71		/* ECDSA signature with SHA-1 hash */
#define ALGO_EC_SHA224			0x72		/* ECDSA signature with SHA-224 hash */
#define ALGO_EC_SHA256			0x73		/* ECDSA signature with SHA-256 hash */
#define ALGO_EC_DH				0x80		/* ECDH key derivation */

#define ID_USER_PIN				0x81		/* User PIN identifier */
#define ID_SO_PIN				0x88		/* Security officer PIN identifier */

#define INIT_RRC_ENABLED		0x01		/* Bit 1 of initialization options */
#define INIT_TRANSPORT_PIN		0x02		/* Bit 2 of initialization options */

/* Information the driver maintains between calls */
typedef struct sc_hsm_private_data {
	const sc_security_env_t *env;
	sc_file_t *dffcp;
	u8 algorithm;
	int noExtLength;
	char *serialno;
	u8 sopin[8];
	u8 *EF_C_DevAut;
	size_t EF_C_DevAut_len;
} sc_hsm_private_data_t;



struct sc_cvc {
	int cpi;							// Certificate profile indicator (0)
	char car[17];						// Certification authority reference

	struct sc_object_id pukoid;			// Public key algorithm object identifier
	u8 *primeOrModulus;					// Prime for ECC or modulus for RSA
	size_t primeOrModuluslen;
	u8 *coefficientAorExponent;			// Coefficient A for ECC or public exponent for RSA
	size_t coefficientAorExponentlen;
	u8 *coefficientB;					// Coefficient B for ECC
	size_t coefficientBlen;
	u8 *basePointG;						// Base point for ECC
	size_t basePointGlen;
	u8 *order;							// Order of the base point for ECC
	size_t orderlen;
	u8 *publicPoint;					// Public point for ECC
	size_t publicPointlen;
	u8 *cofactor;						// Cofactor for ECC
	size_t cofactorlen;

	int modulusSize;					// Size of RSA modulus in bits

	char chr[21];						// Certificate holder reference

	u8 *signature;						// Certificate signature or request self-signed signature
	size_t signatureLen;

	char outer_car[17];					// Instance signing the request
	u8 *outerSignature;					// Request authenticating signature
	size_t outerSignatureLen;
};
typedef struct sc_cvc sc_cvc_t;



struct ec_curve {
	const struct sc_lv_data oid;
	const struct sc_lv_data prime;
	const struct sc_lv_data coefficientA;
	const struct sc_lv_data coefficientB;
	const struct sc_lv_data basePointG;
	const struct sc_lv_data order;
	const struct sc_lv_data coFactor;
};



int sc_pkcs15emu_sc_hsm_decode_cvc(sc_pkcs15_card_t * p15card,
											const u8 ** buf, size_t *buflen,
											sc_cvc_t *cvc);
int sc_pkcs15emu_sc_hsm_encode_cvc(sc_pkcs15_card_t * p15card,
		sc_cvc_t *cvc,
		u8 ** buf, size_t *buflen);
void sc_pkcs15emu_sc_hsm_free_cvc(sc_cvc_t *cvc);
int sc_pkcs15emu_sc_hsm_get_curve(struct ec_curve **curve, u8 *oid, size_t oidlen);
int sc_pkcs15emu_sc_hsm_get_public_key(struct sc_context *ctx, sc_cvc_t *cvc, struct sc_pkcs15_pubkey *pubkey);

/* Known ATRs for SmartCard-HSMs */
extern const struct sc_atr_table sc_hsm_atrs[];
#endif /* SC_HSM_H_ */
