/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#include "config.h"
#if !defined(_MSC_VER) || _MSC_VER >= 1800
#include <inttypes.h>
#endif
#include <string.h>

#ifdef ENABLE_OPENSSL
#include <openssl/x509.h>
#endif

#include "pkcs11-display.h"

/* NSS-specific stuff:
 * https://github.com/nss-dev/nss/blob/d86f709bb4974d10b343c746b6f89dd1ef80259b/lib/util/pkcs11n.h
 */

/*
 * NSS-defined object classes
 */
#define CKO_NSS 0xCE534350

#define CKO_NSS_CRL                (CKO_NSS + 1)
#define CKO_NSS_SMIME              (CKO_NSS + 2)
#define CKO_NSS_TRUST              (CKO_NSS + 3)
#define CKO_NSS_BUILTIN_ROOT_LIST  (CKO_NSS + 4)

/*
 * NSS-defined object attributes
 */

#define CKA_NSS 0xCE534350

#define CKA_NSS_URL                (CKA_NSS +  1)
#define CKA_NSS_EMAIL              (CKA_NSS +  2)
#define CKA_NSS_SMIME_INFO         (CKA_NSS +  3)
#define CKA_NSS_SMIME_TIMESTAMP    (CKA_NSS +  4)
#define CKA_NSS_PKCS8_SALT         (CKA_NSS +  5)
#define CKA_NSS_PASSWORD_CHECK     (CKA_NSS +  6)
#define CKA_NSS_EXPIRES            (CKA_NSS +  7)
#define CKA_NSS_KRL                (CKA_NSS +  8)

#define CKA_NSS_PQG_COUNTER        (CKA_NSS +  20)
#define CKA_NSS_PQG_SEED           (CKA_NSS +  21)
#define CKA_NSS_PQG_H              (CKA_NSS +  22)
#define CKA_NSS_PQG_SEED_BITS      (CKA_NSS +  23)

#define CKA_NSS_TRUST_BASE (CKA_NSS + 0x2000)

/* "Usage" key information */
#define CKA_NSS_TRUST_DIGITAL_SIGNATURE     (CKA_NSS_TRUST_BASE +  1)
#define CKA_NSS_TRUST_NON_REPUDIATION       (CKA_NSS_TRUST_BASE +  2)
#define CKA_NSS_TRUST_KEY_ENCIPHERMENT      (CKA_NSS_TRUST_BASE +  3)
#define CKA_NSS_TRUST_DATA_ENCIPHERMENT     (CKA_NSS_TRUST_BASE +  4)
#define CKA_NSS_TRUST_KEY_AGREEMENT         (CKA_NSS_TRUST_BASE +  5)
#define CKA_NSS_TRUST_KEY_CERT_SIGN         (CKA_NSS_TRUST_BASE +  6)
#define CKA_NSS_TRUST_CRL_SIGN              (CKA_NSS_TRUST_BASE +  7)

/* "Purpose" trust information */
#define CKA_NSS_TRUST_SERVER_AUTH           (CKA_NSS_TRUST_BASE +  8)
#define CKA_NSS_TRUST_CLIENT_AUTH           (CKA_NSS_TRUST_BASE +  9)
#define CKA_NSS_TRUST_CODE_SIGNING          (CKA_NSS_TRUST_BASE + 10)
#define CKA_NSS_TRUST_EMAIL_PROTECTION      (CKA_NSS_TRUST_BASE + 11)
#define CKA_NSS_TRUST_IPSEC_END_SYSTEM      (CKA_NSS_TRUST_BASE + 12)
#define CKA_NSS_TRUST_IPSEC_TUNNEL          (CKA_NSS_TRUST_BASE + 13)
#define CKA_NSS_TRUST_IPSEC_USER            (CKA_NSS_TRUST_BASE + 14)
#define CKA_NSS_TRUST_TIME_STAMPING         (CKA_NSS_TRUST_BASE + 15)
#define CKA_NSS_CERT_SHA1_HASH	            (CKA_NSS_TRUST_BASE + 100)
#define CKA_NSS_CERT_MD5_HASH		        (CKA_NSS_TRUST_BASE + 101)


static char *
buf_spec(CK_VOID_PTR buf_addr, CK_ULONG buf_len)
{
	static char ret[64];

#if !defined(_MSC_VER) || _MSC_VER >= 1800
	const size_t prwidth = sizeof(CK_VOID_PTR) * 2;

	sprintf(ret, "%0*"PRIxPTR" / %ld", (int) prwidth, (uintptr_t) buf_addr,
		buf_len);
#else
	if (sizeof(CK_VOID_PTR) == 4)
		sprintf(ret, "%08lx / %lu", (unsigned long) buf_addr, buf_len);
	else
		sprintf(ret, "%016llx / %lu", (unsigned long long) buf_addr,
			buf_len);
#endif

	return ret;
}

void
print_enum(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg, CK_KEY_TYPE key_type)
{
	enum_spec *spec = (enum_spec*)arg;
	CK_ULONG i;
	CK_ULONG ctype = *((CK_ULONG_PTR)value);

	for(i = 0; i < spec->size; i++) {
		if(spec->specs[i].type == ctype) {
			fprintf(f, "%s\n", spec->specs[i].name);
			return;
		}
	}
	fprintf(f, "Value %lX not found for type %s\n", ctype, spec->name);
}

void
print_boolean(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg, CK_KEY_TYPE key_type)
{
	CK_BYTE i = *((CK_BYTE *)value);
	fprintf(f, i ? "True\n" : "False\n");
}

void
print_generic(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg, CK_KEY_TYPE key_type)
{
	CK_ULONG i;

	if((long)size != -1 && value != NULL) {
		char hex[16*3+1] = {0};
		char ascii[16+1];
		char *hex_ptr = hex, *ascii_ptr = ascii;
		int offset = 0;

		memset(ascii, ' ', sizeof ascii);
		ascii[sizeof ascii -1] = 0;
		fprintf(f, "%s", buf_spec(value, size));
		for(i = 0; i < size; i++) {
			CK_BYTE val;

			if (i && (i % 16) == 0) {
				fprintf(f, "\n    %08X  %s %s", offset, hex, ascii);
				offset += 16;
				hex_ptr = hex;
				ascii_ptr = ascii;
				memset(ascii, ' ', sizeof ascii -1);
			}

			val = ((CK_BYTE *)value)[i];
			/* hex */
			sprintf(hex_ptr, "%02X ", val);
			hex_ptr += 3;
			/* ascii */
			if (val > 31 && val < 128)
				*ascii_ptr = val;
			else
				*ascii_ptr = '.';
			ascii_ptr++;
		}

		/* padding */
		while (strlen(hex) < 3*16)
			strcat(hex, "   ");
		fprintf(f, "\n    %08X  %s %s", offset, hex, ascii);
	}
	else {
		if (value != NULL)
			fprintf(f, "EMPTY");
		else
			fprintf(f, "NULL [size : 0x%lX (%ld)]", size, size);
	}
	fprintf(f, "\n");
}

#ifdef ENABLE_OPENSSL
static void
print_dn(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg, CK_KEY_TYPE key_type)
{
	print_generic(f, type, value, size, arg, key_type);
	if(size && value) {
		X509_NAME *name;
		const unsigned char *tmp = value;

		name = d2i_X509_NAME(NULL, &tmp, size);
		if(name) {
			BIO *bio = BIO_new(BIO_s_file());
			BIO_set_fp(bio, f, 0);
			fprintf(f, "    DN: ");
			X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
			fprintf(f, "\n");
			BIO_free(bio);
		}
	}
}
#endif

static enum_specs ck_mldsa_s[] = {
		{CKP_ML_DSA_44, "CKP_ML_DSA_44"},
		{CKP_ML_DSA_65, "CKP_ML_DSA_65"},
		{CKP_ML_DSA_87, "CKP_ML_DSA_87"},
};

static enum_specs ck_mlkem_s[] = {
		{CKP_ML_KEM_512,	"CKP_ML_KEM_512"},
		{CKP_ML_KEM_768,	"CKP_ML_KEM_768"},
		{CKP_ML_KEM_1024,	"CKP_ML_KEM_1024"},
};

static enum_specs ck_slh_dsa_s[] = {
		{CKP_SLH_DSA_SHA2_128S,	"CKP_SLH_DSA_SHA2_128S"},
		{CKP_SLH_DSA_SHAKE_128S,	"CKP_SLH_DSA_SHAKE_128S"},
		{CKP_SLH_DSA_SHA2_128F,	"CKP_SLH_DSA_SHA2_128F"},
		{CKP_SLH_DSA_SHAKE_128F,	"CKP_SLH_DSA_SHAKE_128F"},
		{CKP_SLH_DSA_SHA2_192S,	"CKP_SLH_DSA_SHA2_192S"},
		{CKP_SLH_DSA_SHAKE_192S,	"CKP_SLH_DSA_SHAKE_192S"},
		{CKP_SLH_DSA_SHA2_192F,	"CKP_SLH_DSA_SHA2_192F"},
		{CKP_SLH_DSA_SHAKE_192F,	"CKP_SLH_DSA_SHAKE_192F"},
		{CKP_SLH_DSA_SHA2_256S,	"CKP_SLH_DSA_SHA2_256S"},
		{CKP_SLH_DSA_SHAKE_256S,	"CKP_SLH_DSA_SHAKE_256S"},
		{CKP_SLH_DSA_SHA2_256F,	"CKP_SLH_DSA_SHA2_256F"},
		{CKP_SLH_DSA_SHAKE_256F,	"CKP_SLH_DSA_SHAKE_256F"},
};

#define SZ_SPECS sizeof(enum_specs)

static enum_spec ck_ml_dsa_t[] = {
		{ML_DSA_T, ck_mldsa_s, sizeof(ck_mldsa_s) / SZ_SPECS, "CK_ML_DSA_PARAMETER_SET_TYPE"},
};
static enum_spec ck_ml_kem_t[] = {
		{ML_KEM_T, ck_mlkem_s, sizeof(ck_mlkem_s) / SZ_SPECS, "CK_ML_KEM_PARAMETER_SET_TYPE"},
};
static enum_spec ck_slh_dsa_t[] = {
		{SLH_DSA_T, ck_slh_dsa_s, sizeof(ck_slh_dsa_s) / SZ_SPECS, "CK_SLH_DSA_PARAMETER_SET_TYPE"},
};

void
print_parameter_set(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg,
		CK_KEY_TYPE key_type)
{
	switch (key_type) {
	case CKK_ML_DSA:
		print_enum(f, type, value, size, ck_ml_dsa_t, key_type);
		break;
	case CKK_ML_KEM:
		print_enum(f, type, value, size, ck_ml_kem_t, key_type);
		break;
	case CKK_SLH_DSA:
		print_enum(f, type, value, size, ck_slh_dsa_t, key_type);
		break;
	default:
		print_generic(f, type, value, size, arg, key_type);
		break;
	}
}

void
print_print(FILE *f, long type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg, CK_KEY_TYPE key_type)
{
	CK_ULONG i, j=0;
	CK_BYTE  c;

	if((long)size != -1) {
		fprintf(f, "%s\n    ", buf_spec(value, size));
		for(i = 0; i < size; i += j) {
			for(j = 0; ((i + j < size) && (j < 32)); j++) {
				if (((j % 4) == 0) && (j != 0))
					fprintf(f, " ");
				c = ((CK_BYTE *)value)[i+j];
				fprintf(f, "%02X", c);
			}
			fprintf(f, "\n    ");

			for(j = 0; ((i + j < size) && (j < 32)); j++) {
				if (((j % 4) == 0) && (j != 0))
					fprintf(f, " ");
				c = ((CK_BYTE *)value)[i + j];
				if((c > 32) && (c < 128))
					fprintf(f, " %c", c);
				else
					fprintf(f, " .");
			}
		}
		if(j == 32)
			fprintf(f, "\n    ");
	}
	else {
		fprintf(f, "EMPTY");
	}
	fprintf(f, "\n");
}

// clang-format off
static enum_specs ck_cls_s[] = {
  {CKO_DATA                 , "CKO_DATA                 "},
  {CKO_CERTIFICATE          , "CKO_CERTIFICATE          "},
  {CKO_PUBLIC_KEY           , "CKO_PUBLIC_KEY           "},
  {CKO_PRIVATE_KEY          , "CKO_PRIVATE_KEY          "},
  {CKO_SECRET_KEY           , "CKO_SECRET_KEY           "},
  {CKO_HW_FEATURE           , "CKO_HW_FEATURE           "},
  {CKO_DOMAIN_PARAMETERS    , "CKO_DOMAIN_PARAMETERS    "},
  {CKO_MECHANISM            , "CKO_MECHANISM            "},
  {CKO_OTP_KEY              , "CKO_OTP_KEY              "},
  {CKO_PROFILE              , "CKO_PROFILE              "},
  {CKO_VALIDATION           , "CKO_VALIDATION           "},
  {CKO_TRUST                , "CKO_TRUST                "},
  {CKO_NSS_CRL              , "CKO_NSS_CRL              "},
  {CKO_NSS_SMIME            , "CKO_NSS_SMIME            "},
  {CKO_NSS_TRUST            , "CKO_NSS_TRUST            "},
  {CKO_NSS_BUILTIN_ROOT_LIST, "CKO_NSS_BUILTIN_ROOT_LIST"},
  {CKO_VENDOR_DEFINED       , "CKO_VENDOR_DEFINED       "}
};

enum_specs ck_profile_s[] = {
  {CKP_INVALID_ID               , "CKP_INVALID_ID               "},
  {CKP_BASELINE_PROVIDER        , "CKP_BASELINE_PROVIDER        "},
  {CKP_EXTENDED_PROVIDER        , "CKP_EXTENDED_PROVIDER        "},
  {CKP_AUTHENTICATION_TOKEN     , "CKP_AUTHENTICATION_TOKEN     "},
  {CKP_PUBLIC_CERTIFICATES_TOKEN, "CKP_PUBLIC_CERTIFICATES_TOKEN"},
  {CKP_COMPLETE_PROVIDER        , "CKP_COMPLETE_PROVIDER        "},
  {CKP_HKDF_TLS_TOKEN           , "CKP_HKDF_TLS_TOKEN           "},
  {CKP_VENDOR_DEFINED           , "CKP_VENDOR_DEFINED           "}
};

static enum_specs ck_crt_s[] = {
  {CKC_X_509          , "CKC_X_509          "},
  {CKC_X_509_ATTR_CERT, "CKC_X_509_ATTR_CERT"},
  {CKC_WTLS           , "CKC_WTLS           "},
};

static enum_specs ck_key_s[] = {
  {CKK_RSA             , "CKK_RSA             "},
  {CKK_DSA             , "CKK_DSA             "},
  {CKK_DH              , "CKK_DH              "},
  {CKK_EC              , "CKK_EC              "},
  {CKK_X9_42_DH        , "CKK_X9_42_DH        "},
  {CKK_KEA             , "CKK_KEA             "},
  {CKK_GENERIC_SECRET  , "CKK_GENERIC_SECRET  "},
  {CKK_RC2             , "CKK_RC2             "},
  {CKK_RC4             , "CKK_RC4             "},
  {CKK_DES             , "CKK_DES             "},
  {CKK_DES2            , "CKK_DES2            "},
  {CKK_DES3            , "CKK_DES3            "},
  {CKK_CAST            , "CKK_CAST            "},
  {CKK_CAST3           , "CKK_CAST3           "},
  {CKK_CAST128         , "CKK_CAST128         "},
  {CKK_RC5             , "CKK_RC5             "},
  {CKK_IDEA            , "CKK_IDEA            "},
  {CKK_SKIPJACK        , "CKK_SKIPJACK        "},
  {CKK_BATON           , "CKK_BATON           "},
  {CKK_JUNIPER         , "CKK_JUNIPER         "},
  {CKK_CDMF            , "CKK_CDMF            "},
  {CKK_AES             , "CKK_AES             "},
  {CKK_BLOWFISH        , "CKK_BLOWFISH        "},
  {CKK_TWOFISH         , "CKK_TWOFISH         "},
  {CKK_SECURID         , "CKK_SECURID         "},
  {CKK_HOTP            , "CKK_HOTP            "},
  {CKK_ACTI            , "CKK_ACTI            "},
  {CKK_CAMELLIA        , "CKK_CAMELLIA        "},
  {CKK_ARIA            , "CKK_ARIA            "},
  {CKK_MD5_HMAC        , "CKK_MD5_HMAC        "},
  {CKK_SHA_1_HMAC      , "CKK_SHA_1_HMAC      "},
  {CKK_RIPEMD128_HMAC  , "CKK_RIPEMD128_HMAC  "},
  {CKK_RIPEMD160_HMAC  , "CKK_RIPEMD160_HMAC  "},
  {CKK_SHA256_HMAC     , "CKK_SHA256_HMAC     "},
  {CKK_SHA384_HMAC     , "CKK_SHA384_HMAC     "},
  {CKK_SHA512_HMAC     , "CKK_SHA512_HMAC     "},
  {CKK_SHA224_HMAC     , "CKK_SHA224_HMAC     "},
  {CKK_SEED            , "CKK_SEED            "},
  {CKK_GOSTR3410       , "CKK_GOSTR3410       "},
  {CKK_GOSTR3411       , "CKK_GOSTR3411       "},
  {CKK_GOST28147       , "CKK_GOST28147       "},
  {CKK_CHACHA20        , "CKK_CHACHA20        "},
  {CKK_POLY1305        , "CKK_POLY1305        "},
  {CKK_AES_XTS         , "CKK_AES_XTS         "},
  {CKK_SHA3_224_HMAC   , "CKK_SHA3_224_HMAC   "},
  {CKK_SHA3_256_HMAC   , "CKK_SHA3_256_HMAC   "},
  {CKK_SHA3_384_HMAC   , "CKK_SHA3_384_HMAC   "},
  {CKK_SHA3_512_HMAC   , "CKK_SHA3_512_HMAC   "},
  {CKK_BLAKE2B_160_HMAC, "CKK_BLAKE2B_160_HMAC"},
  {CKK_BLAKE2B_256_HMAC, "CKK_BLAKE2B_256_HMAC"},
  {CKK_BLAKE2B_384_HMAC, "CKK_BLAKE2B_384_HMAC"},
  {CKK_BLAKE2B_512_HMAC, "CKK_BLAKE2B_512_HMAC"},
  {CKK_SALSA20         , "CKK_SALSA20         "},
  {CKK_X2RATCHET       , "CKK_X2RATCHET       "},
  {CKK_EC_EDWARDS      , "CKK_EC_EDWARDS      "},
  {CKK_EC_MONTGOMERY   , "CKK_EC_MONTOGMERY   "},
  {CKK_HKDF            , "CKK_HKDF            "},
  {CKK_SHA512_224_HMAC , "CKK_SHA512_224_HMAC "},
  {CKK_SHA512_256_HMAC , "CKK_SHA512_256_HMAC "},
  {CKK_SHA512_T_HMAC   , "CKK_SHA512_T_HMAC   "},
  {CKK_HSS             , "CKK_HSS             "},
  {CKK_XMSS            , "CKK_XMSS            "},
  {CKK_XMSSMT          , "CKK_XMSSMT          "},
  {CKK_ML_KEM          , "CKK_ML_KEM          "},
  {CKK_ML_DSA          , "CKK_ML_DSA          "},
  {CKK_SLH_DSA         , "CKK_SLH_DSA         "}
};

static enum_specs ck_mec_s[] = {
  {CKM_RSA_PKCS_KEY_PAIR_GEN              , "CKM_RSA_PKCS_KEY_PAIR_GEN              "},
  {CKM_RSA_PKCS                           , "CKM_RSA_PKCS                           "},
  {CKM_RSA_9796                           , "CKM_RSA_9796                           "},
  {CKM_RSA_X_509                          , "CKM_RSA_X_509                          "},
  {CKM_MD2_RSA_PKCS                       , "CKM_MD2_RSA_PKCS                       "},
  {CKM_MD5_RSA_PKCS                       , "CKM_MD5_RSA_PKCS                       "},
  {CKM_SHA1_RSA_PKCS                      , "CKM_SHA1_RSA_PKCS                      "},
  {CKM_RIPEMD128_RSA_PKCS                 , "CKM_RIPEMD128_RSA_PKCS                 "},
  {CKM_RIPEMD160_RSA_PKCS                 , "CKM_RIPEMD160_RSA_PKCS                 "},
  {CKM_RSA_PKCS_OAEP                      , "CKM_RSA_PKCS_OAEP                      "},
  {CKM_RSA_X9_31_KEY_PAIR_GEN             , "CKM_RSA_X9_31_KEY_PAIR_GEN             "},
  {CKM_RSA_X9_31                          , "CKM_RSA_X9_31                          "},
  {CKM_SHA1_RSA_X9_31                     , "CKM_SHA1_RSA_X9_31                     "},
  {CKM_RSA_PKCS_PSS                       , "CKM_RSA_PKCS_PSS                       "},
  {CKM_SHA1_RSA_PKCS_PSS                  , "CKM_SHA1_RSA_PKCS_PSS                  "},
  {CKM_ML_KEM_KEY_PAIR_GEN                , "CKM_ML_KEM_KEY_PAIR_GEN                "},
  {CKM_DSA_KEY_PAIR_GEN                   , "CKM_DSA_KEY_PAIR_GEN                   "},
  {CKM_DSA                                , "CKM_DSA                                "},
  {CKM_DSA_SHA1                           , "CKM_DSA_SHA1                           "},
  {CKM_DSA_SHA224                         , "CKM_DSA_SHA224                         "},
  {CKM_DSA_SHA256                         , "CKM_DSA_SHA256                         "},
  {CKM_DSA_SHA384                         , "CKM_DSA_SHA384                         "},
  {CKM_DSA_SHA512                         , "CKM_DSA_SHA512                         "},
  {CKM_ML_KEM                             , "CKM_ML_KEM                             "},
  {CKM_DSA_SHA3_224                       , "CKM_DSA_SHA3_224                       "},
  {CKM_DSA_SHA3_256                       , "CKM_DSA_SHA3_256                       "},
  {CKM_DSA_SHA3_384                       , "CKM_DSA_SHA3_384                       "},
  {CKM_DSA_SHA3_512                       , "CKM_DSA_SHA3_512                       "},
  {CKM_ML_DSA_KEY_PAIR_GEN                , "CKM_ML_DSA_KEY_PAIR_GEN                "},
  {CKM_ML_DSA                             , "CKM_ML_DSA                             "},
  {CKM_HASH_ML_DSA                        , "CKM_HASH_ML_DSA                        "},
  {CKM_DH_PKCS_KEY_PAIR_GEN               , "CKM_DH_PKCS_KEY_PAIR_GEN               "},
  {CKM_DH_PKCS_DERIVE                     , "CKM_DH_PKCS_DERIVE                     "},
  {CKM_HASH_ML_DSA_SHA224                 , "CKM_HASH_ML_DSA_SHA224                 "},
  {CKM_HASH_ML_DSA_SHA256                 , "CKM_HASH_ML_DSA_SHA256                 "},
  {CKM_HASH_ML_DSA_SHA384                 , "CKM_HASH_ML_DSA_SHA384                 "},
  {CKM_HASH_ML_DSA_SHA512                 , "CKM_HASH_ML_DSA_SHA512                 "},
  {CKM_HASH_ML_DSA_SHA3_224               , "CKM_HASH_ML_DSA_SHA3_224               "},
  {CKM_HASH_ML_DSA_SHA3_256               , "CKM_HASH_ML_DSA_SHA3_256               "},
  {CKM_HASH_ML_DSA_SHA3_384               , "CKM_HASH_ML_DSA_SHA3_384               "},
  {CKM_HASH_ML_DSA_SHA3_512               , "CKM_HASH_ML_DSA_SHA3_512               "},
  {CKM_HASH_ML_DSA_SHAKE128               , "CKM_HASH_ML_DSA_SHAKE128               "},
  {CKM_HASH_ML_DSA_SHAKE256               , "CKM_HASH_ML_DSA_SHAKE256               "},
  {CKM_SLH_DSA_KEY_PAIR_GEN               , "CKM_SLH_DSA_KEY_PAIR_GEN               "},
  {CKM_SLH_DSA                            , "CKM_SLH_DSA                            "},
  {CKM_X9_42_DH_KEY_PAIR_GEN              , "CKM_X9_42_DH_KEY_PAIR_GEN              "},
  {CKM_X9_42_DH_DERIVE                    , "CKM_X9_42_DH_DERIVE                    "},
  {CKM_X9_42_DH_HYBRID_DERIVE             , "CKM_X9_42_DH_HYBRID_DERIVE             "},
  {CKM_X9_42_MQV_DERIVE                   , "CKM_X9_42_MQV_DERIVE                   "},
  {CKM_HASH_SLH_DSA                       , "CKM_HASH_SLH_DSA                       "},
  {CKM_HASH_SLH_DSA_SHA224                , "CKM_HASH_SLH_DSA_SHA224                "},
  {CKM_HASH_SLH_DSA_SHA256                , "CKM_HASH_SLH_DSA_SHA256                "},
  {CKM_HASH_SLH_DSA_SHA384                , "CKM_HASH_SLH_DSA_SHA384                "},
  {CKM_HASH_SLH_DSA_SHA512                , "CKM_HASH_SLH_DSA_SHA512                "},
  {CKM_HASH_SLH_DSA_SHA3_224              , "CKM_HASH_SLH_DSA_SHA3_224              "},
  {CKM_HASH_SLH_DSA_SHA3_256              , "CKM_HASH_SLH_DSA_SHA3_256              "},
  {CKM_HASH_SLH_DSA_SHA3_384              , "CKM_HASH_SLH_DSA_SHA3_384              "},
  {CKM_HASH_SLH_DSA_SHA3_512              , "CKM_HASH_SLH_DSA_SHA3_512              "},
  {CKM_HASH_SLH_DSA_SHAKE128              , "CKM_HASH_SLH_DSA_SHAKE128              "},
  {CKM_HASH_SLH_DSA_SHAKE256              , "CKM_HASH_SLH_DSA_SHAKE256              "},
  {CKM_SHA256_RSA_PKCS                    , "CKM_SHA256_RSA_PKCS                    "},
  {CKM_SHA384_RSA_PKCS                    , "CKM_SHA384_RSA_PKCS                    "},
  {CKM_SHA512_RSA_PKCS                    , "CKM_SHA512_RSA_PKCS                    "},
  {CKM_SHA256_RSA_PKCS_PSS                , "CKM_SHA256_RSA_PKCS_PSS                "},
  {CKM_SHA384_RSA_PKCS_PSS                , "CKM_SHA384_RSA_PKCS_PSS                "},
  {CKM_SHA512_RSA_PKCS_PSS                , "CKM_SHA512_RSA_PKCS_PSS                "},
  {CKM_SHA224_RSA_PKCS                    , "CKM_SHA224_RSA_PKCS                    "},
  {CKM_SHA224_RSA_PKCS_PSS                , "CKM_SHA224_RSA_PKCS_PSS                "},
  {CKM_SHA512_224                         , "CKM_SHA512_224                         "},
  {CKM_SHA512_224_HMAC                    , "CKM_SHA512_224_HMAC                    "},
  {CKM_SHA512_224_HMAC_GENERAL            , "CKM_SHA512_224_HMAC_GENERAL            "},
  {CKM_SHA512_224_KEY_DERIVATION          , "CKM_SHA512_224_KEY_DERIVATION          "},
  {CKM_SHA512_256                         , "CKM_SHA512_256                         "},
  {CKM_SHA512_256                         , "CKM_SHA512_256                         "},
  {CKM_SHA512_256_HMAC                    , "CKM_SHA512_256_HMAC                    "},
  {CKM_SHA512_256_HMAC_GENERAL            , "CKM_SHA512_256_HMAC_GENERAL            "},
  {CKM_SHA512_256_KEY_DERIVATION          , "CKM_SHA512_256_KEY_DERIVATION          "},
  {CKM_SHA512_T                           , "CKM_SHA512_T                           "},
  {CKM_SHA512_T_HMAC                      , "CKM_SHA512_T_HMAC                      "},
  {CKM_SHA512_T_HMAC_GENERAL              , "CKM_SHA512_T_HMAC_GENERAL              "},
  {CKM_SHA512_T_KEY_DERIVATION            , "CKM_SHA512_T_KEY_DERIVATION            "},
  {CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE   , "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE   "},
  {CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH, "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"},
  {CKM_SHA3_256_RSA_PKCS                  , "CKM_SHA3_256_RSA_PKCS                  "},
  {CKM_SHA3_384_RSA_PKCS                  , "CKM_SHA3_383_RSA_PKCS                  "},
  {CKM_SHA3_512_RSA_PKCS                  , "CKM_SHA3_512_RSA_PKCS                  "},
  {CKM_SHA3_256_RSA_PKCS_PSS              , "CKM_SHA3_256_RSA_PKCS_PSS              "},
  {CKM_SHA3_384_RSA_PKCS_PSS              , "CKM_SHA3_384_RSA_PKCS_PSS              "},
  {CKM_SHA3_512_RSA_PKCS_PSS              , "CKM_SHA3_512_RSA_PKCS_PSS              "},
  {CKM_SHA3_224_RSA_PKCS                  , "CKM_SHA3_224_RSA_PKCS                  "},
  {CKM_SHA3_224_RSA_PKCS_PSS              , "CKM_SHA3_224_RSA_PKCS_PSS              "},
  {CKM_RC2_KEY_GEN                        , "CKM_RC2_KEY_GEN                        "},
  {CKM_RC2_ECB                            , "CKM_RC2_ECB                            "},
  {CKM_RC2_CBC                            , "CKM_RC2_CBC                            "},
  {CKM_RC2_MAC                            , "CKM_RC2_MAC                            "},
  {CKM_RC2_MAC_GENERAL                    , "CKM_RC2_MAC_GENERAL                    "},
  {CKM_RC2_CBC_PAD                        , "CKM_RC2_CBC_PAD                        "},
  {CKM_RC4_KEY_GEN                        , "CKM_RC4_KEY_GEN                        "},
  {CKM_RC4                                , "CKM_RC4                                "},
  {CKM_DES_KEY_GEN                        , "CKM_DES_KEY_GEN                        "},
  {CKM_DES_ECB                            , "CKM_DES_ECB                            "},
  {CKM_DES_CBC                            , "CKM_DES_CBC                            "},
  {CKM_DES_MAC                            , "CKM_DES_MAC                            "},
  {CKM_DES_MAC_GENERAL                    , "CKM_DES_MAC_GENERAL                    "},
  {CKM_DES_CBC_PAD                        , "CKM_DES_CBC_PAD                        "},
  {CKM_DES2_KEY_GEN                       , "CKM_DES2_KEY_GEN                       "},
  {CKM_DES3_KEY_GEN                       , "CKM_DES3_KEY_GEN                       "},
  {CKM_DES3_ECB                           , "CKM_DES3_ECB                           "},
  {CKM_DES3_CBC                           , "CKM_DES3_CBC                           "},
  {CKM_DES3_MAC                           , "CKM_DES3_MAC                           "},
  {CKM_DES3_MAC_GENERAL                   , "CKM_DES3_MAC_GENERAL                   "},
  {CKM_DES3_CBC_PAD                       , "CKM_DES3_CBC_PAD                       "},
  {CKM_DES3_CMAC                          , "CKM_DES3_CMAC                          "},
  {CKM_CDMF_KEY_GEN                       , "CKM_CDMF_KEY_GEN                       "},
  {CKM_CDMF_ECB                           , "CKM_CDMF_ECB                           "},
  {CKM_CDMF_CBC                           , "CKM_CDMF_CBC                           "},
  {CKM_CDMF_MAC                           , "CKM_CDMF_MAC                           "},
  {CKM_CDMF_MAC_GENERAL                   , "CKM_CDMF_MAC_GENERAL                   "},
  {CKM_CDMF_CBC_PAD                       , "CKM_CDMF_CBC_PAD                       "},
  {CKM_DES_OFB64                          , "CKM_DES_OFB64                          "},
  {CKM_DES_OFB8                           , "CKM_DES_OFB8                           "},
  {CKM_DES_CFB64                          , "CKM_DES_CFB64                          "},
  {CKM_DES_CFB8                           , "CKM_DES_CFB8                           "},
  {CKM_MD2                                , "CKM_MD2                                "},
  {CKM_MD2_HMAC                           , "CKM_MD2_HMAC                           "},
  {CKM_MD2_HMAC_GENERAL                   , "CKM_MD2_HMAC_GENERAL                   "},
  {CKM_MD5                                , "CKM_MD5                                "},
  {CKM_MD5_HMAC                           , "CKM_MD5_HMAC                           "},
  {CKM_MD5_HMAC_GENERAL                   , "CKM_MD5_HMAC_GENERAL                   "},
  {CKM_SHA_1                              , "CKM_SHA_1                              "},
  {CKM_SHA_1_HMAC                         , "CKM_SHA_1_HMAC                         "},
  {CKM_SHA_1_HMAC_GENERAL                 , "CKM_SHA_1_HMAC_GENERAL                 "},
  {CKM_RIPEMD128                          , "CKM_RIPEMD128                          "},
  {CKM_RIPEMD128_HMAC                     , "CKM_RIPEMD128_HMAC                     "},
  {CKM_RIPEMD128_HMAC_GENERAL             , "CKM_RIPEMD128_HMAC_GENERAL             "},
  {CKM_RIPEMD160                          , "CKM_RIPEMD160                          "},
  {CKM_RIPEMD160_HMAC                     , "CKM_RIPEMD160_HMAC                     "},
  {CKM_RIPEMD160_HMAC_GENERAL             , "CKM_RIPEMD160_HMAC_GENERAL             "},
  {CKM_SHA256                             , "CKM_SHA256                             "},
  {CKM_SHA256_HMAC                        , "CKM_SHA256_HMAC                        "},
  {CKM_SHA256_HMAC_GENERAL                , "CKM_SHA256_HMAC_GENERAL                "},
  {CKM_SHA224                             , "CKM_SHA224                             "},
  {CKM_SHA224_HMAC                        , "CKM_SHA224_HMAC                        "},
  {CKM_SHA224_HMAC_GENERAL                , "CKM_SHA224_HMAC_GENERAL                "},
  {CKM_SHA384                             , "CKM_SHA384                             "},
  {CKM_SHA384_HMAC                        , "CKM_SHA384_HMAC                        "},
  {CKM_SHA384_HMAC_GENERAL                , "CKM_SHA384_HMAC_GENERAL                "},
  {CKM_SHA512                             , "CKM_SHA512                             "},
  {CKM_SHA512_HMAC                        , "CKM_SHA512_HMAC                        "},
  {CKM_SHA512_HMAC_GENERAL                , "CKM_SHA512_HMAC_GENERAL                "},
  {CKM_SECURID_KEY_GEN                    , "CKM_SECURID_KEY_GEN                    "},
  {CKM_SECURID                            , "CKM_SECURID                            "},
  {CKM_HOTP_KEY_GEN                       , "CKM_HOTP_KEY_GEN                       "},
  {CKM_HOTP                               , "CKM_HOTP                               "},
  {CKM_ACTI                               , "CKM_ACTI                               "},
  {CKM_ACTI_KEY_GEN                       , "CKM_ACTI_KEY_GEN                       "},
  {CKM_SHA3_256                           , "CKM_SHA3_256                           "},
  {CKM_SHA3_256_HMAC                      , "CKM_SHA3_256_HMAC                      "},
  {CKM_SHA3_256_HMAC_GENERAL              , "CKM_SHA3_256_HMAC_GENERAL              "},
  {CKM_SHA3_256_KEY_GEN                   , "CKM_SHA3_256_KEY_GEN                   "},
  {CKM_SHA3_224                           , "CKM_SHA3_224                           "},
  {CKM_SHA3_224_HMAC                      , "CKM_SHA3_224_HMAC                      "},
  {CKM_SHA3_224_HMAC_GENERAL              , "CKM_SHA3_224_HMAC_GENERAL              "},
  {CKM_SHA3_224_KEY_GEN                   , "CKM_SHA3_224_KEY_GEN                   "},
  {CKM_SHA3_384                           , "CKM_SHA3_384                           "},
  {CKM_SHA3_384_HMAC                      , "CKM_SHA3_384_HMAC                      "},
  {CKM_SHA3_384_HMAC_GENERAL              , "CKM_SHA3_384_HMAC_GENERAL              "},
  {CKM_SHA3_384_KEY_GEN                   , "CKM_SHA3_384_KEY_GEN                   "},
  {CKM_SHA3_512                           , "CKM_SHA3_512                           "},
  {CKM_SHA3_512_HMAC                      , "CKM_SHA3_512_HMAC                      "},
  {CKM_SHA3_512_HMAC_GENERAL              , "CKM_SHA3_512_HMAC_GENERAL              "},
  {CKM_SHA3_512_KEY_GEN                   , "CKM_SHA3_512_KEY_GEN                   "},
  {CKM_CAST_KEY_GEN                       , "CKM_CAST_KEY_GEN                       "},
  {CKM_CAST_ECB                           , "CKM_CAST_ECB                           "},
  {CKM_CAST_CBC                           , "CKM_CAST_CBC                           "},
  {CKM_CAST_MAC                           , "CKM_CAST_MAC                           "},
  {CKM_CAST_MAC_GENERAL                   , "CKM_CAST_MAC_GENERAL                   "},
  {CKM_CAST_CBC_PAD                       , "CKM_CAST_CBC_PAD                       "},
  {CKM_CAST3_KEY_GEN                      , "CKM_CAST3_KEY_GEN                      "},
  {CKM_CAST3_ECB                          , "CKM_CAST3_ECB                          "},
  {CKM_CAST3_CBC                          , "CKM_CAST3_CBC                          "},
  {CKM_CAST3_MAC                          , "CKM_CAST3_MAC                          "},
  {CKM_CAST3_MAC_GENERAL                  , "CKM_CAST3_MAC_GENERAL                  "},
  {CKM_CAST3_CBC_PAD                      , "CKM_CAST3_CBC_PAD                      "},
  {CKM_CAST5_KEY_GEN                      , "CKM_CAST5_KEY_GEN                      "},
  {CKM_CAST128_KEY_GEN                    , "CKM_CAST128_KEY_GEN                    "},
  {CKM_CAST5_ECB                          , "CKM_CAST5_ECB                          "},
  {CKM_CAST128_ECB                        , "CKM_CAST128_ECB                        "},
  {CKM_CAST5_CBC                          , "CKM_CAST5_CBC                          "},
  {CKM_CAST128_CBC                        , "CKM_CAST128_CBC                        "},
  {CKM_CAST5_MAC                          , "CKM_CAST5_MAC                          "},
  {CKM_CAST128_MAC                        , "CKM_CAST128_MAC                        "},
  {CKM_CAST5_MAC_GENERAL                  , "CKM_CAST5_MAC_GENERAL                  "},
  {CKM_CAST128_MAC_GENERAL                , "CKM_CAST128_MAC_GENERAL                "},
  {CKM_CAST5_CBC_PAD                      , "CKM_CAST5_CBC_PAD                      "},
  {CKM_CAST128_CBC_PAD                    , "CKM_CAST128_CBC_PAD                    "},
  {CKM_RC5_KEY_GEN                        , "CKM_RC5_KEY_GEN                        "},
  {CKM_RC5_ECB                            , "CKM_RC5_ECB                            "},
  {CKM_RC5_CBC                            , "CKM_RC5_CBC                            "},
  {CKM_RC5_MAC                            , "CKM_RC5_MAC                            "},
  {CKM_RC5_MAC_GENERAL                    , "CKM_RC5_MAC_GENERAL                    "},
  {CKM_RC5_CBC_PAD                        , "CKM_RC5_CBC_PAD                        "},
  {CKM_IDEA_KEY_GEN                       , "CKM_IDEA_KEY_GEN                       "},
  {CKM_IDEA_ECB                           , "CKM_IDEA_ECB                           "},
  {CKM_IDEA_CBC                           , "CKM_IDEA_CBC                           "},
  {CKM_IDEA_MAC                           , "CKM_IDEA_MAC                           "},
  {CKM_IDEA_MAC_GENERAL                   , "CKM_IDEA_MAC_GENERAL                   "},
  {CKM_IDEA_CBC_PAD                       , "CKM_IDEA_CBC_PAD                       "},
  {CKM_GENERIC_SECRET_KEY_GEN             , "CKM_GENERIC_SECRET_KEY_GEN             "},
  {CKM_CONCATENATE_BASE_AND_KEY           , "CKM_CONCATENATE_BASE_AND_KEY           "},
  {CKM_CONCATENATE_BASE_AND_DATA          , "CKM_CONCATENATE_BASE_AND_DATA          "},
  {CKM_CONCATENATE_DATA_AND_BASE          , "CKM_CONCATENATE_DATA_AND_BASE          "},
  {CKM_XOR_BASE_AND_DATA                  , "CKM_XOR_BASE_AND_DATA                  "},
  {CKM_EXTRACT_KEY_FROM_KEY               , "CKM_EXTRACT_KEY_FROM_KEY               "},
  {CKM_SSL3_PRE_MASTER_KEY_GEN            , "CKM_SSL3_PRE_MASTER_KEY_GEN            "},
  {CKM_SSL3_MASTER_KEY_DERIVE             , "CKM_SSL3_MASTER_KEY_DERIVE             "},
  {CKM_SSL3_KEY_AND_MAC_DERIVE            , "CKM_SSL3_KEY_AND_MAC_DERIVE            "},
  {CKM_SSL3_MASTER_KEY_DERIVE_DH          , "CKM_SSL3_MASTER_KEY_DERIVE_DH          "},
  {CKM_TLS_PRE_MASTER_KEY_GEN             , "CKM_TLS_PRE_MASTER_KEY_GEN             "},
  {CKM_TLS_MASTER_KEY_DERIVE              , "CKM_TLS_MASTER_KEY_DERIVE              "},
  {CKM_TLS_KEY_AND_MAC_DERIVE             , "CKM_TLS_KEY_AND_MAC_DERIVE             "},
  {CKM_TLS_MASTER_KEY_DERIVE_DH           , "CKM_TLS_MASTER_KEY_DERIVE_DH           "},
  {CKM_SSL3_MD5_MAC                       , "CKM_SSL3_MD5_MAC                       "},
  {CKM_SSL3_SHA1_MAC                      , "CKM_SSL3_SHA1_MAC                      "},
  {CKM_MD5_KEY_DERIVATION                 , "CKM_MD5_KEY_DERIVATION                 "},
  {CKM_MD2_KEY_DERIVATION                 , "CKM_MD2_KEY_DERIVATION                 "},
  {CKM_SHA1_KEY_DERIVATION                , "CKM_SHA1_KEY_DERIVATION                "},
  {CKM_SHA256_KEY_DERIVATION              , "CKM_SHA256_KEY_DERIVATION              "},
  {CKM_SHA384_KEY_DERIVATION              , "CKM_SHA384_KEY_DERIVATION              "},
  {CKM_SHA512_KEY_DERIVATION              , "CKM_SHA512_KEY_DERIVATION              "},
  {CKM_SHA224_KEY_DERIVATION              , "CKM_SHA224_KEY_DERIVATION              "},
  {CKM_SHA3_256_KEY_DERIVATION            , "CKM_SHA3_256_KEY_DERIVATION            "},
  {CKM_SHA3_256_KEY_DERIVE                , "CKM_SHA3_256_KEY_DERIVE                "},
  {CKM_SHA3_224_KEY_DERIVATION            , "CKM_SHA3_224_KEY_DERIVATION            "},
  {CKM_SHA3_224_KEY_DERIVE                , "CKM_SHA3_224_KEY_DERIVE                "},
  {CKM_SHA3_384_KEY_DERIVATION            , "CKM_SHA3_384_KEY_DERIVATION            "},
  {CKM_SHA3_384_KEY_DERIVE                , "CKM_SHA3_384_KEY_DERIVE                "},
  {CKM_SHA3_512_KEY_DERIVATION            , "CKM_SHA3_512_KEY_DERIVATION            "},
  {CKM_SHA3_512_KEY_DERIVE                , "CKM_SHA3_512_KEY_DERIVE                "},
  {CKM_SHAKE_128_KEY_DERIVATION           , "CKM_SHAKE_128_KEY_DERIVATION           "},
  {CKM_SHAKE_128_KEY_DERIVE               , "CKM_SHAKE_128_KEY_DERIVE               "},
  {CKM_SHAKE_256_KEY_DERIVATION           , "CKM_SHAKE_256_KEY_DERIVATION           "},
  {CKM_SHAKE_256_KEY_DERIVE               , "CKM_SHAKE_256_KEY_DERIVE               "},
  {CKM_PBE_MD2_DES_CBC                    , "CKM_PBE_MD2_DES_CBC                    "},
  {CKM_PBE_MD5_DES_CBC                    , "CKM_PBE_MD5_DES_CBC                    "},
  {CKM_PBE_MD5_CAST_CBC                   , "CKM_PBE_MD5_CAST_CBC                   "},
  {CKM_PBE_MD5_CAST3_CBC                  , "CKM_PBE_MD5_CAST3_CBC                  "},
  {CKM_PBE_MD5_CAST5_CBC                  , "CKM_PBE_MD5_CAST5_CBC                  "},
  {CKM_PBE_MD5_CAST128_CBC                , "CKM_PBE_MD5_CAST128_CBC                "},
  {CKM_PBE_SHA1_CAST5_CBC                 , "CKM_PBE_SHA1_CAST5_CBC                 "},
  {CKM_PBE_SHA1_CAST128_CBC               , "CKM_PBE_SHA1_CAST128_CBC               "},
  {CKM_PBE_SHA1_RC4_128                   , "CKM_PBE_SHA1_RC4_128                   "},
  {CKM_PBE_SHA1_RC4_40                    , "CKM_PBE_SHA1_RC4_40                    "},
  {CKM_PBE_SHA1_DES3_EDE_CBC              , "CKM_PBE_SHA1_DES3_EDE_CBC              "},
  {CKM_PBE_SHA1_DES2_EDE_CBC              , "CKM_PBE_SHA1_DES2_EDE_CBC              "},
  {CKM_PBE_SHA1_RC2_128_CBC               , "CKM_PBE_SHA1_RC2_128_CBC               "},
  {CKM_PBE_SHA1_RC2_40_CBC                , "CKM_PBE_SHA1_RC2_40_CBC                "},
  {CKM_PKCS5_PBKD2                        , "CKM_PKCS5_PBKD2                        "},
  {CKM_WTLS_PRE_MASTER_KEY_GEN            , "CKM_WTLS_PRE_MASTER_KEY_GEN            "},
  {CKM_WTLS_MASTER_KEY_DERIVE             , "CKM_WTLS_MASTER_KEY_DERIVE             "},
  {CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC      , "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC      "},
  {CKM_WTLS_PRF                           , "CKM_WTLS_PRF                           "},
  {CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE     , "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE     "},
  {CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE     , "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE     "},
  {CKM_TLS10_MAC_SERVER                   , "CKM_TLS10_MAC_SERVER                   "},
  {CKM_TLS10_MAC_CLIENT                   , "CKM_TLS10_MAC_CLIENT                   "},
  {CKM_TLS12_MAC                          , "CKM_TLS12_MAC                          "},
  {CKM_TLS12_MAC                          , "CKM_TLS12_MAC                          "},
  {CKM_TLS12_KDF                          , "CKM_TLS12_KDF                          "},
  {CKM_TLS12_MASTER_KEY_DERIVE            , "CKM_TLS12_MASTER_KEY_DERIVE            "},
  {CKM_TLS12_KEY_AND_MAC_DERIVE           , "CKM_TLS12_KEY_AND_MAC_DERIVE           "},
  {CKM_TLS12_MASTER_KEY_DERIVE_DH         , "CKM_TLS12_MASTER_KEY_DERIVE_DH         "},
  {CKM_TLS12_KEY_SAFE_DERIVE              , "CKM_TLS12_KEY_SAFE_DERIVE              "},
  {CKM_TLS_MAC                            , "CKM_TLS_MAC                            "},
  {CKM_TLS_KDF                            , "CKM_TLS_KDF                            "},
  {CKM_KEY_WRAP_LYNKS                     , "CKM_KEY_WRAP_LYNKS                     "},
  {CKM_KEY_WRAP_SET_OAEP                  , "CKM_KEY_WRAP_SET_OAEP                  "},
  {CKM_CMS_SIG                            , "CKM_CMS_SIG                            "},
  {CKM_KIP_DERIVE                         , "CKM_KIP_DERIVE                         "},
  {CKM_KIP_WRAP                           , "CKM_KIP_WRAP                           "},
  {CKM_KIP_MAC                            , "CKM_KIP_MAC                            "},
  {CKM_CAMELLIA_KEY_GEN                   , "CKM_CAMELLIA_KEY_GEN                   "},
  {CKM_CAMELLIA_ECB                       , "CKM_CAMELLIA_ECB                       "},
  {CKM_CAMELLIA_CBC                       , "CKM_CAMELLIA_CBC                       "},
  {CKM_CAMELLIA_MAC                       , "CKM_CAMELLIA_MAC                       "},
  {CKM_CAMELLIA_MAC_GENERAL               , "CKM_CAMELLIA_MAC_GENERAL               "},
  {CKM_CAMELLIA_CBC_PAD                   , "CKM_CAMELLIA_CBC_PAD                   "},
  {CKM_CAMELLIA_ECB_ENCRYPT_DATA          , "CKM_CAMELLIA_ECB_ENCRYPT_DATA          "},
  {CKM_CAMELLIA_CBC_ENCRYPT_DATA          , "CKM_CAMELLIA_CBC_ENCRYPT_DATA          "},
  {CKM_CAMELLIA_CTR                       , "CKM_CAMELLIA_CTR                       "},
  {CKM_ARIA_KEY_GEN                       , "CKM_ARIA_KEY_GEN                       "},
  {CKM_ARIA_ECB                           , "CKM_ARIA_ECB                           "},
  {CKM_ARIA_CBC                           , "CKM_ARIA_CBC                           "},
  {CKM_ARIA_MAC                           , "CKM_ARIA_MAC                           "},
  {CKM_ARIA_MAC_GENERAL                   , "CKM_ARIA_MAC_GENERAL                   "},
  {CKM_ARIA_CBC_PAD                       , "CKM_ARIA_CBC_PAD                       "},
  {CKM_ARIA_ECB_ENCRYPT_DATA              , "CKM_ARIA_ECB_ENCRYPT_DATA              "},
  {CKM_ARIA_CBC_ENCRYPT_DATA              , "CKM_ARIA_CBC_ENCRYPT_DATA              "},
  {CKM_SKIPJACK_KEY_GEN                   , "CKM_SKIPJACK_KEY_GEN                   "},
  {CKM_SKIPJACK_ECB64                     , "CKM_SKIPJACK_ECB64                     "},
  {CKM_SKIPJACK_CBC64                     , "CKM_SKIPJACK_CBC64                     "},
  {CKM_SKIPJACK_OFB64                     , "CKM_SKIPJACK_OFB64                     "},
  {CKM_SKIPJACK_CFB64                     , "CKM_SKIPJACK_CFB64                     "},
  {CKM_SKIPJACK_CFB32                     , "CKM_SKIPJACK_CFB32                     "},
  {CKM_SKIPJACK_CFB16                     , "CKM_SKIPJACK_CFB16                     "},
  {CKM_SKIPJACK_CFB8                      , "CKM_SKIPJACK_CFB8                      "},
  {CKM_SKIPJACK_WRAP                      , "CKM_SKIPJACK_WRAP                      "},
  {CKM_SKIPJACK_PRIVATE_WRAP              , "CKM_SKIPJACK_PRIVATE_WRAP              "},
  {CKM_SKIPJACK_RELAYX                    , "CKM_SKIPJACK_RELAYX                    "},
  {CKM_KEA_KEY_PAIR_GEN                   , "CKM_KEA_KEY_PAIR_GEN                   "},
  {CKM_KEA_KEY_DERIVE                     , "CKM_KEA_KEY_DERIVE                     "},
  {CKM_FORTEZZA_TIMESTAMP                 , "CKM_FORTEZZA_TIMESTAMP                 "},
  {CKM_BATON_KEY_GEN                      , "CKM_BATON_KEY_GEN                      "},
  {CKM_BATON_ECB128                       , "CKM_BATON_ECB128                       "},
  {CKM_BATON_ECB96                        , "CKM_BATON_ECB96                        "},
  {CKM_BATON_CBC128                       , "CKM_BATON_CBC128                       "},
  {CKM_BATON_COUNTER                      , "CKM_BATON_COUNTER                      "},
  {CKM_BATON_SHUFFLE                      , "CKM_BATON_SHUFFLE                      "},
  {CKM_BATON_WRAP                         , "CKM_BATON_WRAP                         "},
  {CKM_EC_KEY_PAIR_GEN                    , "CKM_EC_KEY_PAIR_GEN                    "},
  {CKM_ECDSA                              , "CKM_ECDSA                              "},
  {CKM_ECDSA_SHA1                         , "CKM_ECDSA_SHA1                         "},
  {CKM_ECDSA_SHA224                       , "CKM_ECDSA_SHA224                       "},
  {CKM_ECDSA_SHA256                       , "CKM_ECDSA_SHA256                       "},
  {CKM_ECDSA_SHA384                       , "CKM_ECDSA_SHA384                       "},
  {CKM_ECDSA_SHA512                       , "CKM_ECDSA_SHA512                       "},
  {CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS       , "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS       "},
  {CKM_ECDH1_DERIVE                       , "CKM_ECDH1_DERIVE                       "},
  {CKM_ECDH1_COFACTOR_DERIVE              , "CKM_ECDH1_COFACTOR_DERIVE              "},
  {CKM_ECMQV_DERIVE                       , "CKM_ECMQV_DERIVE                       "},
  {CKM_ECDH_AES_KEY_WRAP                  , "CKM_ECDH_AES_KEY_WRAP                  "},
  {CKM_RSA_AES_KEY_WRAP                   , "CKM_RSA_AES_KEY_WRAP                   "},
  {CKM_JUNIPER_KEY_GEN                    , "CKM_JUNIPER_KEY_GEN                    "},
  {CKM_JUNIPER_ECB128                     , "CKM_JUNIPER_ECB128                     "},
  {CKM_JUNIPER_CBC128                     , "CKM_JUNIPER_CBC128                     "},
  {CKM_JUNIPER_COUNTER                    , "CKM_JUNIPER_COUNTER                    "},
  {CKM_JUNIPER_SHUFFLE                    , "CKM_JUNIPER_SHUFFLE                    "},
  {CKM_JUNIPER_WRAP                       , "CKM_JUNIPER_WRAP                       "},
  {CKM_FASTHASH                           , "CKM_FASTHASH                           "},
  {CKM_AES_XTS                            , "CKM_AES_XTS                            "},
  {CKM_AES_XTS_KEY_GEN                    , "CKM_AES_XTS_KEY_GEN                    "},
  {CKM_AES_KEY_GEN                        , "CKM_AES_KEY_GEN                        "},
  {CKM_AES_ECB                            , "CKM_AES_ECB                            "},
  {CKM_AES_CBC                            , "CKM_AES_CBC                            "},
  {CKM_AES_MAC                            , "CKM_AES_MAC                            "},
  {CKM_AES_MAC_GENERAL                    , "CKM_AES_MAC_GENERAL                    "},
  {CKM_AES_CBC_PAD                        , "CKM_AES_CBC_PAD                        "},
  {CKM_AES_CTR                            , "CKM_AES_CTR                            "},
  {CKM_AES_GCM                            , "CKM_AES_GCM                            "},
  {CKM_AES_CCM                            , "CKM_AES_CCM                            "},
  {CKM_AES_CMAC                           , "CKM_AES_CMAC                           "},
  {CKM_AES_CTS                            , "CKM_AES_CTS                            "},
  {CKM_AES_CMAC_GENERAL                   , "CKM_AES_CMAC_GENERAL                   "},
  {CKM_AES_XCBC_MAC                       , "CKM_AES_XCBC_MAC                       "},
  {CKM_AES_XCBC_MAC_96                    , "CKM_AES_XCBC_MAC_96                    "},
  {CKM_AES_GMAC                           , "CKM_AES_GMAC                           "},
  {CKM_AES_XCBC_MAC_96                    , "CKM_AES_XCBC_MAC_96                    "},
  {CKM_BLOWFISH_KEY_GEN                   , "CKM_BLOWFISH_KEY_GEN                   "},
  {CKM_BLOWFISH_CBC                       , "CKM_BLOWFISH_CBC                       "},
  {CKM_TWOFISH_KEY_GEN                    , "CKM_TWOFISH_KEY_GEN                    "},
  {CKM_TWOFISH_CBC                        , "CKM_TWOFISH_CBC                        "},
  {CKM_BLOWFISH_CBC_PAD                   , "CKM_BLOWFISH_CBC_PAD                   "},
  {CKM_TWOFISH_CBC_PAD                    , "CKM_TWOFISH_CBC_PAD                    "},
  {CKM_AES_XCBC_MAC_96                    , "CKM_AES_XCBC_MAC_96                    "},
  {CKM_DES_ECB_ENCRYPT_DATA               , "CKM_DES_ECB_ENCRYPT_DATA               "},
  {CKM_DES_CBC_ENCRYPT_DATA               , "CKM_DES_CBC_ENCRYPT_DATA               "},
  {CKM_DES3_ECB_ENCRYPT_DATA              , "CKM_DES3_ECB_ENCRYPT_DATA              "},
  {CKM_DES3_CBC_ENCRYPT_DATA              , "CKM_DES3_CBC_ENCRYPT_DATA              "},
  {CKM_AES_ECB_ENCRYPT_DATA               , "CKM_AES_ECB_ENCRYPT_DATA               "},
  {CKM_AES_CBC_ENCRYPT_DATA               , "CKM_AES_CBC_ENCRYPT_DATA               "},
  {CKM_GOSTR3410_KEY_PAIR_GEN             , "CKM_GOSTR3410_KEY_PAIR_GEN             "},
  {CKM_GOSTR3410                          , "CKM_GOSTR3410                          "},
  {CKM_GOSTR3410_WITH_GOSTR3411           , "CKM_GOSTR3410_WITH_GOSTR3411           "},
  {CKM_GOSTR3410_KEY_WRAP                 , "CKM_GOSTR3410_KEY_WRAP                 "},
  {CKM_GOSTR3410_DERIVE                   , "CKM_GOSTR3410_DERIVE                   "},
  {CKM_GOSTR3411                          , "CKM_GOSTR3411                          "},
  {CKM_GOSTR3411_HMAC                     , "CKM_GOSTR3411_HMAC                     "},
  {CKM_GOST28147_KEY_GEN                  , "CKM_GOST28147_KEY_GEN                  "},
  {CKM_GOST28147_ECB                      , "CKM_GOST28147_ECB                      "},
  {CKM_GOST28147                          , "CKM_GOST28147                          "},
  {CKM_GOST28147_MAC                      , "CKM_GOST28147_MAC                      "},
  {CKM_GOST28147_KEY_WRAP                 , "CKM_GOST28147_KEY_WRAP                 "},
  {CKM_CHACHA20_KEY_GEN                   , "CKM_CHACHA20_KEY_GEN                   "},
  {CKM_CHACHA20                           , "CKM_CHACHA20                           "},
  {CKM_POLY1305_KEY_GEN                   , "CKM_POLY1305_KEY_GEN                   "},
  {CKM_POLY1305                           , "CKM_POLY1305                           "},
  {CKM_DSA_PARAMETER_GEN                  , "CKM_DSA_PARAMETER_GEN                  "},
  {CKM_DH_PKCS_PARAMETER_GEN              , "CKM_DH_PKCS_PARAMETER_GEN              "},
  {CKM_X9_42_DH_PARAMETER_GEN             , "CKM_X9_42_DH_PARAMETER_GEN             "},
  {CKM_DSA_PROBABILISTIC_PARAMETER_GEN    , "CKM_DSA_PROBABILISTIC_PARAMETER_GEN    "},
  {CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN     , "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN     "},
  {CKM_DSA_FIPS_G_GEN                     , "CKM_DSA_FIPS_G_GEN                     "},
  {CKM_AES_OFB                            , "CKM_AES_OFB                            "},
  {CKM_AES_CFB64                          , "CKM_AES_CFB64                          "},
  {CKM_AES_CFB8                           , "CKM_AES_CFB8                           "},
  {CKM_AES_CFB128                         , "CKM_AES_CFB128                         "},
  {CKM_AES_CFB1                           , "CKM_AES_CFB1                           "},
  {CKM_AES_KEY_WRAP                       , "CKM_AES_KEY_WRAP                       "},
  {CKM_AES_KEY_WRAP_PAD                   , "CKM_AES_KEY_WRAP_PAD                   "},
  {CKM_AES_KEY_WRAP_KWP                   , "CKM_AES_KEY_WRAP_KWP                   "},
  {CKM_AES_KEY_WRAP_PKCS7                 , "CKM_AES_KEY_WRAP_PKCS7                 "},
  {CKM_RSA_PKCS_TPM_1_1                   , "CKM_RSA_PKCS_TPM_1_1                   "},
  {CKM_RSA_PKCS_OAEP_TPM_1_1              , "CKM_RSA_PKCS_OAEP_TPM_1_1              "},
  {CKM_SHA_1_KEY_GEN                      , "CKM_SHA_1_KEY_GEN                      "},
  {CKM_SHA224_KEY_GEN                     , "CKM_SHA224_KEY_GEN                     "},
  {CKM_SHA256_KEY_GEN                     , "CKM_SHA256_KEY_GEN                     "},
  {CKM_SHA384_KEY_GEN                     , "CKM_SHA384_KEY_GEN                     "},
  {CKM_SHA512_KEY_GEN                     , "CKM_SHA512_KEY_GEN                     "},
  {CKM_SHA512_224_KEY_GEN                 , "CKM_SHA512_224_KEY_GEN                 "},
  {CKM_SHA512_256_KEY_GEN                 , "CKM_SHA512_256_KEY_GEN                 "},
  {CKM_SHA512_T_KEY_GEN                   , "CKM_SHA512_T_KEY_GEN                   "},
  {CKM_NULL                               , "CKM_NULL                               "},
  {CKM_BLAKE2B_160                        , "CKM_BLAKE2B_160                        "},
  {CKM_BLAKE2B_160_HMAC                   , "CKM_BLAKE2B_160_HMAC                   "},
  {CKM_BLAKE2B_160_HMAC_GENERAL           , "CKM_BLAKE2B_160_HMAC_GENERAL           "},
  {CKM_BLAKE2B_160_KEY_DERIVE             , "CKM_BLAKE2B_160_KEY_DERIVE             "},
  {CKM_BLAKE2B_160_KEY_GEN                , "CKM_BLAKE2B_160_KEY_GEN                "},
  {CKM_BLAKE2B_256                        , "CKM_BLAKE2B_256                        "},
  {CKM_BLAKE2B_256_HMAC                   , "CKM_BLAKE2B_256_HMAC                   "},
  {CKM_BLAKE2B_256_HMAC_GENERAL           , "CKM_BLAKE2B_256_HMAC_GENERAL           "},
  {CKM_BLAKE2B_256_KEY_DERIVE             , "CKM_BLAKE2B_256_KEY_DERIVE             "},
  {CKM_BLAKE2B_256_KEY_GEN                , "CKM_BLAKE2B_256_KEY_GEN                "},
  {CKM_BLAKE2B_384                        , "CKM_BLAKE2B_384                        "},
  {CKM_BLAKE2B_384_HMAC                   , "CKM_BLAKE2B_384_HMAC                   "},
  {CKM_BLAKE2B_384_HMAC_GENERAL           , "CKM_BLAKE2B_384_HMAC_GENERAL           "},
  {CKM_BLAKE2B_384_KEY_DERIVE             , "CKM_BLAKE2B_384_KEY_DERIVE             "},
  {CKM_BLAKE2B_384_KEY_GEN                , "CKM_BLAKE2B_384_KEY_GEN                "},
  {CKM_BLAKE2B_512                        , "CKM_BLAKE2B_512                        "},
  {CKM_BLAKE2B_512_HMAC                   , "CKM_BLAKE2B_512_HMAC                   "},
  {CKM_BLAKE2B_512_HMAC_GENERAL           , "CKM_BLAKE2B_512_HMAC_GENERAL           "},
  {CKM_BLAKE2B_512_KEY_DERIVE             , "CKM_BLAKE2B_512_KEY_DERIVE             "},
  {CKM_BLAKE2B_512_KEY_GEN                , "CKM_BLAKE2B_512_KEY_GEN                "},
  {CKM_SALSA20                            , "CKM_SALSA20                            "},
  {CKM_CHACHA20_POLY1305                  , "CKM_CHACHA20_POLY1305                  "},
  {CKM_SALSA20_POLY1305                   , "CKM_SALSA20_POLY1305                   "},
  {CKM_X3DH_INITIALIZE                    , "CKM_X3DH_INITIALIZE                    "},
  {CKM_X3DH_RESPOND                       , "CKM_X3DH_RESPOND                       "},
  {CKM_X2RATCHET_INITIALIZE               , "CKM_X2RATCHET_INITIALIZE               "},
  {CKM_X2RATCHET_RESPOND                  , "CKM_X2RATCHET_RESPOND                  "},
  {CKM_X2RATCHET_ENCRYPT                  , "CKM_X2RATCHET_ENCRYPT                  "},
  {CKM_X2RATCHET_DECRYPT                  , "CKM_X2RATCHET_DECRYPT                  "},
  {CKM_XEDDSA                             , "CKM_XEDDSA                             "},
  {CKM_HKDF_DERIVE                        , "CKM_HKDF_DERIVE                        "},
  {CKM_HKDF_DATA                          , "CKM_HKDF_DATA                          "},
  {CKM_HKDF_KEY_GEN                       , "CKM_HKDF_KEY_GEN                       "},
  {CKM_SALSA20_KEY_GEN                    , "CKM_SALSA20_KEY_GEN                    "},
  {CKM_ECDSA_SHA3_224                     , "CKM_ECDSA_SHA3_224                     "},
  {CKM_ECDSA_SHA3_256                     , "CKM_ECDSA_SHA3_256                     "},
  {CKM_ECDSA_SHA3_384                     , "CKM_ECDSA_SHA3_384                     "},
  {CKM_ECDSA_SHA3_512                     , "CKM_ECDSA_SHA3_512                     "},
  {CKM_EC_EDWARDS_KEY_PAIR_GEN            , "CKM_EC_EDWARDS_KEY_PAIR_GEN            "},
  {CKM_EC_MONTGOMERY_KEY_PAIR_GEN         , "CKM_EC_MONTGOMERY_KEY_PAIR_GEN         "},
  {CKM_EDDSA                              , "CKM_EDDSA                              "},
  {CKM_SP800_108_COUNTER_KDF              , "CKM_SP800_108_COUNTER_KDF              "},
  {CKM_SP800_108_FEEDBACK_KDF             , "CKM_SP800_108_FEEDBACK_KDF             "},
  {CKM_SP800_108_DOUBLE_PIPELINE_KDF      , "CKM_SP800_108_DOUBLE_PIPELINE_KDF      "},
  {CKM_IKE2_PRF_PLUS_DERIVE               , "CKM_IKE2_PRF_PLUS_DERIVE               "},
  {CKM_IKE_PRF_DERIVE                     , "CKM_IKE_PRF_DERIVE                     "},
  {CKM_IKE1_PRF_DERIVE                    , "CKM_IKE1_PRF_DERIVE                    "},
  {CKM_IKE1_EXTENDED_DERIVE               , "CKM_IKE1_EXTENDED_DERIVE               "},
  {CKM_HSS_KEY_PAIR_GEN                   , "CKM_HSS_KEY_PAIR_GEN                   "},
  {CKM_HSS                                , "CKM_HSS                                "},
  {CKM_XMSS_KEY_PAIR_GEN                  , "CKM_XMSS_KEY_PAIR_GEN                  "},
  {CKM_XMSSMT_KEY_PAIR_GEN                , "CKM_XMSSMT_KEY_PAIR_GEN                "},
  {CKM_XMSS                               , "CKM_XMSS                               "},
  {CKM_XMSSMT                             , "CKM_XMSSMT                             "},
  {CKM_ECDH_X_AES_KEY_WRAP                , "CKM_ECDH_X_AES_KEY_WRAP                "},
  {CKM_ECDH_COF_AES_KEY_WRAP              , "CKM_ECDH_COF_AES_KEY_WRAP              "},
  {CKM_PUB_KEY_FROM_PRIV_KEY              , "CKM_PUB_KEY_FROM_PRIV_KEY              "},
  {CKM_XMSS                               , "CKM_XMSS                               "},
  {CKM_XMSS                               , "CKM_XMSS                               "},
  {CKM_XMSS                               , "CKM_XMSS                               "},
  {CKM_VENDOR_DEFINED                     , "CKM_VENDOR_DEFINED                     "}
};

static enum_specs ck_mgf_s[] = {
  { CKG_MGF1_SHA1    , "CKG_MGF1_SHA1    " },
  { CKG_MGF1_SHA224  , "CKG_MGF1_SHA224  " },
  { CKG_MGF1_SHA256  , "CKG_MGF1_SHA256  " },
  { CKG_MGF1_SHA384  , "CKG_MGF1_SHA384  " },
  { CKG_MGF1_SHA512  , "CKG_MGF1_SHA512  " },
  { CKG_MGF1_SHA3_224, "CKG_MGF1_SHA3_224" },
  { CKG_MGF1_SHA3_256, "CKG_MGF1_SHA3_256" },
  { CKG_MGF1_SHA3_384, "CKG_MGF1_SHA3_384" },
  { CKG_MGF1_SHA3_512, "CKG_MGF1_SHA3_512" },
};

static enum_specs ck_generate_s[] = {
  {CKG_NO_GENERATE         , "CKG_NO_GENERATE         "},
  {CKG_GENERATE            , "CKG_GENERATE            "},
  {CKG_GENERATE_COUNTER    , "CKG_GENERATE_COUNTER    "},
  {CKG_GENERATE_RANDOM     , "CKG_GENERATE_RANDOM     "},
  {CKG_GENERATE_COUNTER_XOR, "CKG_GENERATE_COUNTER_XOR"},
};

static enum_specs ck_hw_s[] = {
  {CKH_MONOTONIC_COUNTER, "CKH_MONOTONIC_COUNTER"},
  {CKH_CLOCK            , "CKH_CLOCK            "},
  {CKH_USER_INTERFACE   , "CKH_USER_INTERFACE   "}
};

static enum_specs ck_hg_s[] = {
  {CKH_HEDGE_PREFERRED       , "CKH_HEDGE_PREFERRED       "},
  {CKH_HEDGE_REQUIRED        , "CKH_HEDGE_REQUIRED        "},
  {CKH_DETERMINISTIC_REQUIRED, "CKH_DETERMINISTIC_REQUIRED"}
};

static enum_specs ck_not_s[] = {
  {CKN_SURRENDER  , "CKN_SURRENDER       "},
  {CKN_OTP_CHANGED, "CKN_OTP_CHANGED     "}
};

static enum_specs ck_err_s[] = {
  {CKR_OK,                               "CKR_OK"},
  {CKR_CANCEL,                           "CKR_CANCEL"},
  {CKR_HOST_MEMORY,                      "CKR_HOST_MEMORY"},
  {CKR_SLOT_ID_INVALID,                  "CKR_SLOT_ID_INVALID"},
  {CKR_GENERAL_ERROR,                    "CKR_GENERAL_ERROR"},
  {CKR_FUNCTION_FAILED,                  "CKR_FUNCTION_FAILED"},
  {CKR_ARGUMENTS_BAD,                    "CKR_ARGUMENTS_BAD"},
  {CKR_NO_EVENT,                         "CKR_NO_EVENT"},
  {CKR_NEED_TO_CREATE_THREADS,           "CKR_NEED_TO_CREATE_THREADS"},
  {CKR_CANT_LOCK,                        "CKR_CANT_LOCK"},
  {CKR_ATTRIBUTE_READ_ONLY,              "CKR_ATTRIBUTE_READ_ONLY"},
  {CKR_ATTRIBUTE_SENSITIVE,              "CKR_ATTRIBUTE_SENSITIVE"},
  {CKR_ATTRIBUTE_TYPE_INVALID,           "CKR_ATTRIBUTE_TYPE_INVALID"},
  {CKR_ATTRIBUTE_VALUE_INVALID,          "CKR_ATTRIBUTE_VALUE_INVALID"},
  {CKR_ACTION_PROHIBITED,                "CKR_ACTION_PROHIBITED"},
  {CKR_DATA_INVALID,                     "CKR_DATA_INVALID"},
  {CKR_DATA_LEN_RANGE,                   "CKR_DATA_LEN_RANGE"},
  {CKR_DEVICE_ERROR,                     "CKR_DEVICE_ERROR"},
  {CKR_DEVICE_MEMORY,                    "CKR_DEVICE_MEMORY"},
  {CKR_DEVICE_REMOVED,                   "CKR_DEVICE_REMOVED"},
  {CKR_ENCRYPTED_DATA_INVALID,           "CKR_ENCRYPTED_DATA_INVALID"},
  {CKR_ENCRYPTED_DATA_LEN_RANGE,         "CKR_ENCRYPTED_DATA_LEN_RANGE"},
  {CKR_AEAD_DECRYPT_FAILED,              "CKR_AEAD_DECRYPT_FAILED"},
  {CKR_FUNCTION_CANCELED,                "CKR_FUNCTION_CANCELED"},
  {CKR_FUNCTION_NOT_PARALLEL,            "CKR_FUNCTION_NOT_PARALLEL"},
  {CKR_FUNCTION_NOT_SUPPORTED,           "CKR_FUNCTION_NOT_SUPPORTED"},
  {CKR_KEY_HANDLE_INVALID,               "CKR_KEY_HANDLE_INVALID"},
  {CKR_KEY_SIZE_RANGE,                   "CKR_KEY_SIZE_RANGE"},
  {CKR_KEY_TYPE_INCONSISTENT,            "CKR_KEY_TYPE_INCONSISTENT"},
  {CKR_KEY_NOT_NEEDED,                   "CKR_KEY_NOT_NEEDED"},
  {CKR_KEY_CHANGED,                      "CKR_KEY_CHANGED"},
  {CKR_KEY_NEEDED,                       "CKR_KEY_NEEDED"},
  {CKR_KEY_INDIGESTIBLE,                 "CKR_KEY_INDIGESTIBLE"},
  {CKR_KEY_FUNCTION_NOT_PERMITTED,       "CKR_KEY_FUNCTION_NOT_PERMITTED"},
  {CKR_KEY_NOT_WRAPPABLE,                "CKR_KEY_NOT_WRAPPABLE"},
  {CKR_KEY_UNEXTRACTABLE,                "CKR_KEY_UNEXTRACTABLE"},
  {CKR_MECHANISM_INVALID,                "CKR_MECHANISM_INVALID"},
  {CKR_MECHANISM_PARAM_INVALID,          "CKR_MECHANISM_PARAM_INVALID"},
  {CKR_OBJECT_HANDLE_INVALID,            "CKR_OBJECT_HANDLE_INVALID"},
  {CKR_OPERATION_ACTIVE,                 "CKR_OPERATION_ACTIVE"},
  {CKR_OPERATION_NOT_INITIALIZED,        "CKR_OPERATION_NOT_INITIALIZED"},
  {CKR_PIN_INCORRECT,                    "CKR_PIN_INCORRECT"},
  {CKR_PIN_INVALID,                      "CKR_PIN_INVALID"},
  {CKR_PIN_LEN_RANGE,                    "CKR_PIN_LEN_RANGE"},
  {CKR_PIN_EXPIRED,                      "CKR_PIN_EXPIRED"},
  {CKR_PIN_LOCKED,                       "CKR_PIN_LOCKED"},
  {CKR_SESSION_CLOSED,                   "CKR_SESSION_CLOSED"},
  {CKR_SESSION_COUNT,                    "CKR_SESSION_COUNT"},
  {CKR_SESSION_HANDLE_INVALID,           "CKR_SESSION_HANDLE_INVALID"},
  {CKR_SESSION_PARALLEL_NOT_SUPPORTED,   "CKR_SESSION_PARALLEL_NOT_SUPPORTED"},
  {CKR_SESSION_READ_ONLY,                "CKR_SESSION_READ_ONLY"},
  {CKR_SESSION_EXISTS,                   "CKR_SESSION_EXISTS"},
  {CKR_SESSION_READ_ONLY_EXISTS,         "CKR_SESSION_READ_ONLY_EXISTS"},
  {CKR_SESSION_READ_WRITE_SO_EXISTS,     "CKR_SESSION_READ_WRITE_SO_EXISTS"},
  {CKR_SIGNATURE_INVALID,                "CKR_SIGNATURE_INVALID"},
  {CKR_SIGNATURE_LEN_RANGE,              "CKR_SIGNATURE_LEN_RANGE"},
  {CKR_TEMPLATE_INCOMPLETE,              "CKR_TEMPLATE_INCOMPLETE"},
  {CKR_TEMPLATE_INCONSISTENT,            "CKR_TEMPLATE_INCONSISTENT"},
  {CKR_TOKEN_NOT_PRESENT,                "CKR_TOKEN_NOT_PRESENT"},
  {CKR_TOKEN_NOT_RECOGNIZED,             "CKR_TOKEN_NOT_RECOGNIZED"},
  {CKR_TOKEN_WRITE_PROTECTED,            "CKR_TOKEN_WRITE_PROTECTED"},
  {CKR_UNWRAPPING_KEY_HANDLE_INVALID,    "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
  {CKR_UNWRAPPING_KEY_SIZE_RANGE,        "CKR_UNWRAPPING_KEY_SIZE_RANGE"},
  {CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"},
  {CKR_USER_ALREADY_LOGGED_IN,           "CKR_USER_ALREADY_LOGGED_IN"},
  {CKR_USER_NOT_LOGGED_IN,               "CKR_USER_NOT_LOGGED_IN"},
  {CKR_USER_PIN_NOT_INITIALIZED,         "CKR_USER_PIN_NOT_INITIALIZED"},
  {CKR_USER_TYPE_INVALID,                "CKR_USER_TYPE_INVALID"},
  {CKR_USER_ANOTHER_ALREADY_LOGGED_IN,   "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"},
  {CKR_USER_TOO_MANY_TYPES,              "CKR_USER_TOO_MANY_TYPES"},
  {CKR_WRAPPED_KEY_INVALID,              "CKR_WRAPPED_KEY_INVALID"},
  {CKR_WRAPPED_KEY_LEN_RANGE,            "CKR_WRAPPED_KEY_LEN_RANGE"},
  {CKR_WRAPPING_KEY_HANDLE_INVALID,      "CKR_WRAPPING_KEY_HANDLE_INVALID"},
  {CKR_WRAPPING_KEY_SIZE_RANGE,          "CKR_WRAPPING_KEY_SIZE_RANGE"},
  {CKR_WRAPPING_KEY_TYPE_INCONSISTENT,   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"},
  {CKR_RANDOM_SEED_NOT_SUPPORTED,        "CKR_RANDOM_SEED_NOT_SUPPORTED"},
  {CKR_RANDOM_NO_RNG,                    "CKR_RANDOM_NO_RNG"},
  {CKR_DOMAIN_PARAMS_INVALID,            "CKR_DOMAIN_PARAMS_INVALID"},
  {CKR_CURVE_NOT_SUPPORTED,              "CKR_CURVE_NOT_SUPPORTED"},
  {CKR_BUFFER_TOO_SMALL,                 "CKR_BUFFER_TOO_SMALL"},
  {CKR_SAVED_STATE_INVALID,              "CKR_SAVED_STATE_INVALID"},
  {CKR_INFORMATION_SENSITIVE,            "CKR_INFORMATION_SENSITIVE"},
  {CKR_STATE_UNSAVEABLE,                 "CKR_STATE_UNSAVEABLE"},
  {CKR_CRYPTOKI_NOT_INITIALIZED,         "CKR_CRYPTOKI_NOT_INITIALIZED"},
  {CKR_CRYPTOKI_ALREADY_INITIALIZED,     "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
  {CKR_MUTEX_BAD,                        "CKR_MUTEX_BAD"},
  {CKR_MUTEX_NOT_LOCKED,                 "CKR_MUTEX_NOT_LOCKED"},
  {CKR_NEW_PIN_MODE,                     "CKR_NEW_PIN_MODE"},
  {CKR_NEXT_OTP,                         "CKR_NEXT_OTP"},
  {CKR_EXCEEDED_MAX_ITERATIONS,          "CKR_EXCEEDED_MAX_ITERATIONS"},
  {CKR_FIPS_SELF_TEST_FAILED,            "CKR_FIPS_SELF_TEST_FAILED"},
  {CKR_LIBRARY_LOAD_FAILED,              "CKR_LIBRARY_LOAD_FAILED"},
  {CKR_PIN_TOO_WEAK,                     "CKR_PIN_TOO_WEAK"},
  {CKR_PUBLIC_KEY_INVALID,               "CKR_PUBLIC_KEY_INVALID"},
  {CKR_FUNCTION_REJECTED,                "CKR_FUNCTION_REJECTED"},
  {CKR_TOKEN_RESOURCE_EXCEEDED,          "CKR_TOKEN_RESOURCE_EXCEEDED"},
  {CKR_OPERATION_CANCEL_FAILED,          "CKR_OPERATION_CANCEL_FAILED"},
  {CKR_KEY_EXHAUSTED,                    "CKR_KEY_EXHAUSTED"},
  {CKR_PENDING,                          "CKR_PENDING"},
  {CKR_SESSION_ASYNC_NOT_SUPPORTED,      "CKR_SESSION_ASYNC_NOT_SUPPORTED"},
  {CKR_SEED_RANDOM_REQUIRED,             "CKR_SEED_RANDOM_REQUIRED"},
  {CKR_OPERATION_NOT_VALIDATED,          "CKR_OPERATION_NOT_VALIDATED"},
  {CKR_TOKEN_NOT_INITIALIZED,            "CKR_TOKEN_NOT_INITIALIZED"},
  {CKR_PARAMETER_SET_NOT_SUPPORTED,      "CKR_PARAMETER_SET_NOT_SUPPORTED"},
  {CKR_VENDOR_DEFINED,                   "CKR_VENDOR_DEFINED"}
};

static enum_specs ck_usr_s[] = {
  {CKU_SO,   "CKU_SO"},
  {CKU_USER, "CKU_USER"},
  {CKU_CONTEXT_SPECIFIC, "CKU_CONTEXT_SPECIFIC"}
};

static enum_specs ck_sta_s[] = {
  {CKS_RO_PUBLIC_SESSION, "CKS_RO_PUBLIC_SESSION"},
  {CKS_RO_USER_FUNCTIONS, "CKS_RO_USER_FUNCTIONS"},
  {CKS_RW_PUBLIC_SESSION, "CKS_RW_PUBLIC_SESSION"},
  {CKS_RW_USER_FUNCTIONS, "CKS_RW_USER_FUNCTIONS"},
  {CKS_RW_SO_FUNCTIONS,   "CKS_RW_SO_FUNCTIONS"}
};

static enum_specs ck_tru_s[] = {
  {CKT_TRUST_UNKNOWN,           "CKT_TRUST_UNKNOWN"},
  {CKT_TRUSTED,                 "CKT_TRUSTED"},
  {CKT_TRUST_ANCHOR,            "CKT_TRUST_ANCHOR"},
  {CKT_NOT_TRUSTED,             "CKT_NOT_TRUSTED"},
  {CKT_TRUST_MUST_VERIFY_TRUST, "CKT_TRUST_MUST_VERIFY_TRUST"}
};

static enum_specs ck_auth_s[] = {
  {CKV_AUTHORITY_TYPE_UNSPECIFIED,     "CKV_AUTHORITY_TYPE_UNSPECIFIED"},
  {CKV_AUTHORITY_TYPE_NIST_CMVP,       "CKV_AUTHORITY_TYPE_NIST_CMVP"},
  {CKV_AUTHORITY_TYPE_COMMON_CRITERIA, "CKV_AUTHORITY_TYPE_COMMON_CRITERIA"}
};

static enum_specs ck_val_s[] = {
  {CKV_TYPE_UNSPECIFIED, "CKV_TYPE_UNSPECIFIED"},
  {CKV_TYPE_SOFTWARE,    "CKV_TYPE_SOFTWARE"},
  {CKV_TYPE_HARDWARE,    "CKV_TYPE_HARDWARE"},
  {CKV_TYPE_FIRMWARE,    "CKV_TYPE_FIRMWARE"},
  {CKV_TYPE_HYBRID,      "CKV_TYPE_HYBRID"}
};

static enum_specs ck_ckd_s[] = {
  {CKD_NULL,                 "CKD_NULL"},
  {CKD_SHA1_KDF,             "CKD_SHA1_KDF"},
  {CKD_SHA1_KDF_ASN1,        "CKD_SHA1_KDF_ASN1"},
  {CKD_SHA1_KDF_CONCATENATE, "CKD_SHA1_KDF_CONCATENATE"},
  {CKD_SHA224_KDF,           "CKD_SHA224_KDF"},
  {CKD_SHA256_KDF,           "CKD_SHA256_KDF"},
  {CKD_SHA384_KDF,           "CKD_SHA384_KDF"},
  {CKD_SHA512_KDF,           "CKD_SHA512_KDF"},
  {CKD_CPDIVERSIFY_KDF,      "CKD_CPDIVERSIFY_KDF"},
  {CKD_SHA3_224_KDF,         "CKD_SHA3_224_KDF"},
  {CKD_SHA3_256_KDF,         "CKD_SHA3_256_KDF"},
  {CKD_SHA3_384_KDF,         "CKD_SHA3_384_KDF"},
  {CKD_SHA3_512_KDF,         "CKD_SHA3_512_KDF"},
  {CKD_SHA1_KDF_SP800,       "CKD_SHA1_KDF_SP800"},
  {CKD_SHA224_KDF_SP800,     "CKD_SHA224_KDF_SP800"},
  {CKD_SHA256_KDF_SP800,     "CKD_SHA256_KDF_SP800"},
  {CKD_SHA384_KDF_SP800,     "CKD_SHA384_KDF_SP800"},
  {CKD_SHA512_KDF_SP800,     "CKD_SHA512_KDF_SP800"},
  {CKD_SHA3_224_KDF_SP800,   "CKD_SHA3_224_KDF_SP800"},
  {CKD_SHA3_256_KDF_SP800,   "CKD_SHA3_256_KDF_SP800"},
  {CKD_SHA3_384_KDF_SP800,   "CKD_SHA3_384_KDF_SP800"},
  {CKD_SHA3_512_KDF_SP800,   "CKD_SHA3_512_KDF_SP800"},
  {CKD_BLAKE2B_160_KDF,      "CKD_BLAKE2B_160_KDF"},
  {CKD_BLAKE2B_256_KDF,      "CKD_BLAKE2B_256_KDF"},
  {CKD_BLAKE2B_384_KDF,      "CKD_BLAKE2B_384_KDF"},
  {CKD_BLAKE2B_512_KDF,      "CKD_BLAKE2B_512_KDF"}
};

enum_spec ck_types[] = {
  {OBJ_T,      ck_cls_s,      sizeof(ck_cls_s) / SZ_SPECS,      "CK_OBJECT_CLASS"              },
  {PROFILE_T,  ck_profile_s,  sizeof(ck_profile_s)/SZ_SPECS,    "CK_PROFILE"                   },
  {KEY_T,      ck_key_s,      sizeof(ck_key_s) / SZ_SPECS,      "CK_KEY_TYPE"                  },
  {CRT_T,      ck_crt_s,      sizeof(ck_crt_s) / SZ_SPECS,      "CK_CERTIFICATE_TYPE"          },
  {MEC_T,      ck_mec_s,      sizeof(ck_mec_s) / SZ_SPECS,      "CK_MECHANISM_TYPE"            },
  {MGF_T,      ck_mgf_s,      sizeof(ck_mgf_s) / SZ_SPECS,      "CK_RSA_PKCS_MGF_TYPE"         },
  {GENERATE_T, ck_generate_s, sizeof(ck_generate_s) / SZ_SPECS, "CK_GENERATOR_FUNCTION"        },
  {USR_T,      ck_usr_s,      sizeof(ck_usr_s) / SZ_SPECS,      "CK_USER_TYPE"                 },
  {STA_T,      ck_sta_s,      sizeof(ck_sta_s) / SZ_SPECS,      "CK_STATE"                     },
  {CKD_T,      ck_ckd_s,      sizeof(ck_ckd_s) / SZ_SPECS,      "CK_EC_KDF_TYPE"               },
  {RV_T,       ck_err_s,      sizeof(ck_err_s) / SZ_SPECS,      "CK_RV"                        },
  {HW_T,       ck_hw_s,       sizeof(ck_hw_s) / SZ_SPECS,       "CK_HW_FEATURE_TYPE"           },
  {HG_T,       ck_hg_s,       sizeof(ck_hg_s) / SZ_SPECS,       "CK_HEDGE_TYPE"                },
  {NOT_T,      ck_not_s,      sizeof(ck_not_s) / SZ_SPECS,      "CK_NOTIFICATION"              },
  /* CKP PBKD2, ML-DSA, ML_KEM, SLH-DSA missing*/
  {TRU_T,      ck_tru_s,      sizeof(ck_tru_s) / SZ_SPECS,      "CK_TRUST"                     },
  {AUTH_T,     ck_auth_s,     sizeof(ck_auth_s) / SZ_SPECS,     "CK_VALIDATION_AUTHORITY_TYPE" },
  {VAL_T,      ck_val_s,      sizeof(ck_val_s) / SZ_SPECS,      "CK_VALIDATION_TYPE"           },
  {ML_DSA_T,   ck_mldsa_s,    sizeof(ck_mldsa_s) / SZ_SPECS,    "CK_ML_DSA_PARAMETER_SET_TYPE" },
  {ML_KEM_T,   ck_mlkem_s,    sizeof(ck_mlkem_s) / SZ_SPECS,    "CK_ML_KEM_PARAMETER_SET_TYPE" },
  {SLH_DSA_T,  ck_slh_dsa_s,  sizeof(ck_slh_dsa_s) / SZ_SPECS,  "CK_SLH_DSA_PARAMETER_SET_TYPE"},
};



static enum_spec ck_key_t[] = { { KEY_T, ck_key_s, sizeof(ck_key_s) / SZ_SPECS, "CK_KEY_TYPE" } };
static enum_spec ck_cls_t[] = { { OBJ_T, ck_cls_s, sizeof(ck_cls_s) / SZ_SPECS, "CK_OBJECT_CLASS" } };
static enum_spec ck_crt_t[] = { { CRT_T, ck_crt_s, sizeof(ck_crt_s) / SZ_SPECS, "CK_CERTIFICATE_TYPE" } };
static enum_spec ck_profile_t[] = { { PROFILE_T, ck_profile_s, sizeof(ck_profile_s) / SZ_SPECS, "CK_PROFILE" } };

type_spec ck_attribute_specs[] = {
  { CKA_CLASS             , "CKA_CLASS            ", print_enum,    ck_cls_t },
  { CKA_TOKEN             , "CKA_TOKEN            ", print_boolean, NULL },
  { CKA_PRIVATE           , "CKA_PRIVATE          ", print_boolean, NULL },
  { CKA_LABEL             , "CKA_LABEL            ", print_print,   NULL },
  { CKA_APPLICATION       , "CKA_APPLICATION      ", print_print,   NULL },
  { CKA_VALUE             , "CKA_VALUE            ", print_generic, NULL },
  { CKA_OBJECT_ID         , "CKA_OBJECT_ID        ", print_generic, NULL },
  { CKA_CERTIFICATE_TYPE  , "CKA_CERTIFICATE_TYPE ", print_enum,    ck_crt_t },
#ifdef ENABLE_OPENSSL
  { CKA_ISSUER            , "CKA_ISSUER           ", print_dn,      NULL },
#else
  { CKA_ISSUER            , "CKA_ISSUER           ", print_generic, NULL },
#endif
  { CKA_SERIAL_NUMBER     , "CKA_SERIAL_NUMBER    ", print_generic, NULL },
#ifdef ENABLE_OPENSSL
  { CKA_AC_ISSUER         , "CKA_AC_ISSUER        ", print_dn,      NULL },
#else
  { CKA_AC_ISSUER         , "CKA_AC_ISSUER        ", print_generic, NULL },
#endif
  { CKA_OWNER             , "CKA_OWNER            ", print_generic, NULL },
  { CKA_ATTR_TYPES        , "CKA_ATTR_TYPES       ", print_generic, NULL },
  { CKA_TRUSTED           , "CKA_TRUSTED          ", print_generic, NULL },
  { CKA_CERTIFICATE_CATEGORY, "CKA_CERTIFICATE_CATEGORY ", print_generic, NULL },
  { CKA_JAVA_MIDP_SECURITY_DOMAIN, "CKA_JAVA_MIDP_SECURITY_DOMAIN ", print_generic, NULL },
  { CKA_URL               , "CKA_URL              ", print_generic, NULL },
  { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY ", print_generic, NULL },
  { CKA_HASH_OF_ISSUER_PUBLIC_KEY, "CKA_HASH_OF_ISSUER_PUBLIC_KEY ", print_generic, NULL },
  { CKA_CHECK_VALUE       , "CKA_CHECK_VALUE      ", print_generic, NULL },
  { CKA_KEY_TYPE          , "CKA_KEY_TYPE         ", print_enum,    ck_key_t },
#ifdef ENABLE_OPENSSL
  { CKA_SUBJECT           , "CKA_SUBJECT          ", print_dn,      NULL },
#else
  { CKA_SUBJECT           , "CKA_SUBJECT          ", print_generic, NULL },
#endif
  { CKA_ID                , "CKA_ID               ", print_generic, NULL },
  { CKA_UNIQUE_ID         , "CKA_UNIQUE_ID        ", print_generic, NULL },
  { CKA_SENSITIVE         , "CKA_SENSITIVE        ", print_boolean, NULL },
  { CKA_ENCRYPT           , "CKA_ENCRYPT          ", print_boolean, NULL },
  { CKA_DECRYPT           , "CKA_DECRYPT          ", print_boolean, NULL },
  { CKA_WRAP              , "CKA_WRAP             ", print_boolean, NULL },
  { CKA_UNWRAP            , "CKA_UNWRAP           ", print_boolean, NULL },
  { CKA_SIGN              , "CKA_SIGN             ", print_boolean, NULL },
  { CKA_SIGN_RECOVER      , "CKA_SIGN_RECOVER     ", print_boolean, NULL },
  { CKA_VERIFY            , "CKA_VERIFY           ", print_boolean, NULL },
  { CKA_VERIFY_RECOVER    , "CKA_VERIFY_RECOVER   ", print_boolean, NULL },
  { CKA_DERIVE            , "CKA_DERIVE           ", print_boolean, NULL },
  { CKA_START_DATE        , "CKA_START_DATE       ", print_generic, NULL },
  { CKA_END_DATE          , "CKA_END_DATE         ", print_generic, NULL },
  { CKA_MODULUS           , "CKA_MODULUS          ", print_generic, NULL },
  { CKA_MODULUS_BITS      , "CKA_MODULUS_BITS     ", print_generic, NULL },
  { CKA_PUBLIC_EXPONENT   , "CKA_PUBLIC_EXPONENT  ", print_generic, NULL },
  { CKA_PRIVATE_EXPONENT  , "CKA_PRIVATE_EXPONENT ", print_generic, NULL },
  { CKA_PRIME_1           , "CKA_PRIME_1          ", print_generic, NULL },
  { CKA_PRIME_2           , "CKA_PRIME_2          ", print_generic, NULL },
  { CKA_EXPONENT_1        , "CKA_EXPONENT_1       ", print_generic, NULL },
  { CKA_EXPONENT_2        , "CKA_EXPONENT_2       ", print_generic, NULL },
  { CKA_COEFFICIENT       , "CKA_COEFFICIENT      ", print_generic, NULL },
  { CKA_PUBLIC_KEY_INFO   , "CKA_PUBLIC_KEY_INFO  ", print_generic, NULL },
  { CKA_PRIME             , "CKA_PRIME            ", print_generic, NULL },
  { CKA_SUBPRIME          , "CKA_SUBPRIME         ", print_generic, NULL },
  { CKA_BASE              , "CKA_BASE             ", print_generic, NULL },
  { CKA_PRIME_BITS        , "CKA_PRIME_BITS       ", print_generic, NULL },
  { CKA_SUB_PRIME_BITS    , "CKA_SUB_PRIME_BITS   ", print_generic, NULL },
  { CKA_VALUE_BITS        , "CKA_VALUE_BITS       ", print_generic, NULL },
  { CKA_VALUE_LEN         , "CKA_VALUE_LEN        ", print_generic, NULL },
  { CKA_EXTRACTABLE       , "CKA_EXTRACTABLE      ", print_boolean, NULL },
  { CKA_LOCAL             , "CKA_LOCAL            ", print_boolean, NULL },
  { CKA_NEVER_EXTRACTABLE , "CKA_NEVER_EXTRACTABLE", print_boolean, NULL },
  { CKA_ALWAYS_SENSITIVE  , "CKA_ALWAYS_SENSITIVE ", print_boolean, NULL },
  { CKA_KEY_GEN_MECHANISM , "CKA_KEY_GEN_MECHANISM", print_boolean, NULL },
  { CKA_MODIFIABLE        , "CKA_MODIFIABLE       ", print_boolean, NULL },
  { CKA_COPYABLE          , "CKA_COPYABLE         ", print_boolean, NULL },
  { CKA_EC_PARAMS         , "CKA_EC_PARAMS        ", print_generic, NULL },
  { CKA_ECDSA_PARAMS      , "CKA_ECDSA_PARAMS     ", print_generic, NULL },
  { CKA_EC_POINT          , "CKA_EC_POINT         ", print_generic, NULL },
  { CKA_SECONDARY_AUTH    , "CKA_SECONDARY_AUTH   ", print_generic, NULL },
  { CKA_AUTH_PIN_FLAGS    , "CKA_AUTH_PIN_FLAGS   ", print_generic, NULL },
  { CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE ", print_boolean, NULL },
  { CKA_WRAP_WITH_TRUSTED , "CKA_WRAP_WITH_TRUSTED ", print_generic, NULL },
  { CKA_OTP_FORMAT        , "CKA_OTP_FORMAT       ", print_generic, NULL },
  { CKA_OTP_LENGTH        , "CKA_OTP_LENGTH       ", print_generic, NULL },
  { CKA_OTP_TIME_INTERVAL , "CKA_OTP_TIME_INTERVAL ", print_generic, NULL },
  { CKA_OTP_USER_FRIENDLY_MODE, "CKA_OTP_USER_FRIENDLY_MODE ", print_boolean, NULL },
  { CKA_OTP_CHALLENGE_REQUIREMENT, "CKA_OTP_CHALLENGE_REQUIREMENT ", print_generic, NULL },
  { CKA_OTP_TIME_REQUIREMENT, "CKA_OTP_TIME_REQUIREMENT ", print_generic, NULL },
  { CKA_OTP_COUNTER_REQUIREMENT, "CKA_OTP_COUNTER_REQUIREMENT ", print_generic, NULL },
  { CKA_OTP_PIN_REQUIREMENT, "CKA_OTP_PIN_REQUIREMENT ", print_generic, NULL },
  { CKA_OTP_COUNTER       , "CKA_OTP_COUNTER      ", print_generic, NULL },
  { CKA_OTP_TIME          , "CKA_OTP_TIME         ", print_print, NULL },
  { CKA_OTP_USER_IDENTIFIER, "CKA_OTP_USER_IDENTIFIER ", print_print, NULL },
  { CKA_OTP_SERVICE_IDENTIFIER, "CKA_OTP_SERVICE_IDENTIFIER ", print_print, NULL },
  { CKA_OTP_SERVICE_LOGO  , "CKA_OTP_SERVICE_LOGO ", print_generic, NULL },
  { CKA_OTP_SERVICE_LOGO_TYPE, "CKA_OTP_SERVICE_LOGO_TYPE ", print_print, NULL },
  { CKA_GOSTR3410_PARAMS  , "CKA_GOSTR3410_PARAMS ", print_generic, NULL },
  { CKA_GOSTR3411_PARAMS  , "CKA_GOSTR3411_PARAMS ", print_generic, NULL },
  { CKA_GOST28147_PARAMS  , "CKA_GOST28147_PARAMS ", print_generic, NULL },
  { CKA_HW_FEATURE_TYPE   , "CKA_HW_FEATURE_TYPE  ", print_generic, NULL },
  { CKA_RESET_ON_INIT     , "CKA_RESET_ON_INIT    ", print_generic, NULL },
  { CKA_HAS_RESET         , "CKA_HAS_RESET        ", print_generic, NULL },
  { CKA_PIXEL_X           , "CKA_PIXEL_X          ", print_generic, NULL },
  { CKA_PIXEL_Y           , "CKA_PIXEL_Y          ", print_generic, NULL },
  { CKA_RESOLUTION        , "CKA_RESOLUTION       ", print_generic, NULL },
  { CKA_CHAR_ROWS         , "CKA_CHAR_ROWS        ", print_generic, NULL },
  { CKA_CHAR_COLUMNS      , "CKA_CHAR_COLUMNS     ", print_generic, NULL },
  { CKA_COLOR             , "CKA_COLOR            ", print_generic, NULL },
  { CKA_BITS_PER_PIXEL    , "CKA_BITS_PER_PIXEL   ", print_generic, NULL },
  { CKA_CHAR_SETS         , "CKA_CHAR_SETS        ", print_generic, NULL },
  { CKA_ENCODING_METHODS  , "CKA_ENCODING_METHODS ", print_generic, NULL },
  { CKA_MIME_TYPES        , "CKA_MIME_TYPES       ", print_generic, NULL },
  { CKA_MECHANISM_TYPE    , "CKA_MECHANISM_TYPE   ", print_generic, NULL },
  { CKA_PROFILE_ID        , "CKA_PROFILE_ID       ", print_enum, ck_profile_t },
  { CKA_REQUIRED_CMS_ATTRIBUTES, "CKA_REQUIRED_CMS_ATTRIBUTES ", print_generic, NULL },
  { CKA_DEFAULT_CMS_ATTRIBUTES, "CKA_DEFAULT_CMS_ATTRIBUTES ", print_generic, NULL },
  { CKA_SUPPORTED_CMS_ATTRIBUTES, "CKA_SUPPORTED_CMS_ATTRIBUTES ", print_generic, NULL },

  // NEW in PKCS#11 v3.2
  { CKA_X2RATCHET_BAG     , "CKA_X2RATCHET_BAG     ", print_generic, NULL },
  { CKA_X2RATCHET_BAGSIZE , "CKA_X2RATCHET_BAGSIZE ", print_generic, NULL },
  { CKA_X2RATCHET_BOBS1STMSG, "CKA_X2RATCHET_BOBS1STMSG ", print_generic, NULL },
  { CKA_X2RATCHET_CKR     , "CKA_X2RATCHET_CKR     ", print_generic, NULL },
  { CKA_X2RATCHET_CKS     , "CKA_X2RATCHET_CKS "   , print_generic, NULL },
  { CKA_X2RATCHET_DHP     , "CKA_X2RATCHET_DHP "   , print_generic, NULL },
  { CKA_X2RATCHET_DHR     , "CKA_X2RATCHET_DHR "   , print_generic, NULL },
  { CKA_X2RATCHET_DHS     , "CKA_X2RATCHET_DHS "   , print_generic, NULL },
  { CKA_X2RATCHET_HKR     , "CKA_X2RATCHET_HKR ", print_generic, NULL },
  { CKA_X2RATCHET_HKS     , "CKA_X2RATCHET_HKS ", print_generic, NULL },
  { CKA_X2RATCHET_ISALICE , "CKA_X2RATCHET_ISALICE ", print_generic, NULL },
  { CKA_X2RATCHET_NHKR    , "CKA_X2RATCHET_NHKR ", print_generic, NULL },
  { CKA_X2RATCHET_NHKS    , "CKA_X2RATCHET_NHKS ", print_generic, NULL },
  { CKA_X2RATCHET_NR      , "CKA_X2RATCHET_NR ", print_generic, NULL },
  { CKA_X2RATCHET_NS      , "CKA_X2RATCHET_NS ", print_generic, NULL },
  { CKA_X2RATCHET_PNS     , "CKA_X2RATCHET_PNS ", print_generic, NULL },
  { CKA_X2RATCHET_RK      , "CKA_X2RATCHET_BAGSIZE ", print_generic, NULL },
  { CKA_HSS_LEVELS        , "CKA_HSS_LEVELS ", print_generic, NULL },
  { CKA_HSS_LMS_TYPE      , "CKA_HSS_LMS_TYPE ", print_generic, NULL },
  { CKA_HSS_LMOTS_TYPE    , "CKA_HSS_LMOTS_TYPE ", print_generic, NULL },
  { CKA_HSS_LMS_TYPES     , "CKA_HSS_LMS_TYPES ", print_generic, NULL },
  { CKA_HSS_LMOTS_TYPES   , "CKA_HSS_LMOTS_TYPES ", print_generic, NULL },
  { CKA_HSS_KEYS_REMAINING, "CKA_HSS_KEYS_REMAINING ", print_generic, NULL },
  { CKA_PARAMETER_SET     , "CKA_PARAMETER_SET ", print_parameter_set, NULL },
  { CKA_OBJECT_VALIDATION_FLAGS     , "CKA_OBJECT_VALIDATION_FLAGS ", print_generic, NULL },
  { CKA_VALIDATION_TYPE     , "CKA_VALIDATION_TYPE ", print_generic, NULL },
  { CKA_VALIDATION_VERSION     , "CKA_VALIDATION_VERSION ", print_generic, NULL },
  { CKA_VALIDATION_LEVEL     , "CKA_VALIDATION_LEVEL ", print_generic, NULL },
  { CKA_VALIDATION_MODULE_ID     , "CKA_VALIDATION_MODULE_ID ", print_generic, NULL },
  { CKA_VALIDATION_FLAG     , "CKA_VALIDATION_FLAG ", print_generic, NULL },
  { CKA_VALIDATION_AUTHORITY_TYPE     , "CKA_VALIDATION_AUTHORITY_TYPE ", print_generic, NULL },
  { CKA_VALIDATION_COUNTRY     , "CKA_VALIDATION_COUNTRY ", print_generic, NULL },
  { CKA_VALIDATION_CERTIFICATE_IDENTIFIER     , "CKA_VALIDATION_CERTIFICATE_IDENTIFIER ", print_generic, NULL },
  { CKA_VALIDATION_CERTIFICATE_URI     , "CKA_VALIDATION_CERTIFICATE_URI ", print_generic, NULL },
  { CKA_VALIDATION_VENDOR_URI     , "CKA_VALIDATION_VENDOR_URI ", print_generic, NULL },
  { CKA_VALIDATION_PROFILE     , "CKA_VALIDATION_PROFILE ", print_generic, NULL },
  { CKA_OBJECT_VALIDATION_FLAGS     , "CKA_OBJECT_VALIDATION_FLAGS ", print_generic, NULL },
  { CKA_ENCAPSULATE_TEMPLATE     , "CKA_ENCAPSULATE_TEMPLATE ", print_generic, NULL },
  { CKA_DECAPSULATE_TEMPLATE     , "CKA_DECAPSULATE_TEMPLATE ", print_generic, NULL },
  { CKA_TRUST_SERVER_AUTH     , "CKA_TRUST_SERVER_AUTH ", print_generic, NULL },
  { CKA_TRUST_CLIENT_AUTH     , "CKA_TRUST_CLIENT_AUTH ", print_generic, NULL },
  { CKA_TRUST_CODE_SIGNING     , "CKA_TRUST_CODE_SIGNING ", print_generic, NULL },
  { CKA_TRUST_EMAIL_PROTECTION     , "CKA_TRUST_EMAIL_PROTECTION ", print_generic, NULL },
  { CKA_TRUST_IPSEC_IKE     , "CKA_TRUST_IPSEC_IKE ", print_generic, NULL },
  { CKA_TRUST_TIME_STAMPING     , "CKA_TRUST_TIME_STAMPING ", print_generic, NULL },
  { CKA_TRUST_OCSP_SIGNING     , "CKA_TRUST_OCSP_SIGNING ", print_generic, NULL },
  { CKA_ENCAPSULATE     , "CKA_ENCAPSULATE ", print_boolean, NULL },
  { CKA_DECAPSULATE     , "CKA_DECAPSULATE ", print_boolean, NULL },
  { CKA_HASH_OF_CERTIFICATE     , "CKA_HASH_OF_CERTIFICATE ", print_generic, NULL },
  { CKA_PUBLIC_CRC64_VALUE     , "CKA_PUBLIC_CRC64_VALUE ", print_generic, NULL },
  { CKA_SEED     , "CKA_SEED ", print_generic, NULL },
  { CKA_WRAP_TEMPLATE     , "CKA_WRAP_TEMPLATE    ", print_generic, NULL },
  { CKA_UNWRAP_TEMPLATE   , "CKA_UNWRAP_TEMPLATE  ", print_generic, NULL },
  { CKA_DERIVE_TEMPLATE   , "CKA_DERIVE_TEMPLATE  ", print_generic, NULL },
  { CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS ", print_generic, NULL },
  { CKA_NSS_URL, "CKA_NSS_URL(NSS)                         ", print_generic, NULL },
  { CKA_NSS_EMAIL, "CKA_NSS_EMAIL(NSS)                     ", print_generic, NULL },
  { CKA_NSS_SMIME_INFO, "CKA_NSS_SMIME_INFO(NSS)           ", print_boolean, NULL },
  { CKA_NSS_SMIME_TIMESTAMP, "CKA_NSS_SMIME_TIMESTAMP(NSS) ", print_generic, NULL },
  { CKA_NSS_PKCS8_SALT, "CKA_NSS_PKCS8_SALT(NSS)           ", print_generic, NULL },
  { CKA_NSS_PASSWORD_CHECK, "CKA_NSS_PASSWORD_CHECK(NSS)   ", print_generic, NULL },
  { CKA_NSS_EXPIRES, "CKA_NSS_EXPIRES(NSS)                 ", print_generic, NULL },
  { CKA_NSS_KRL, "CKA_NSS_KRL(NSS)                         ", print_generic, NULL },
  { CKA_NSS_PQG_COUNTER, "CKA_NSS_PQG_COUNTER(NSS)         ", print_generic, NULL },
  { CKA_NSS_PQG_SEED, "CKA_NSS_PQG_SEED(NSS)               ", print_generic, NULL },
  { CKA_NSS_PQG_H, "CKA_NSS_PQG_H(NSS)                     ", print_generic, NULL },
  { CKA_NSS_PQG_SEED_BITS, "CKA_NSS_PQG_SEED_BITS(NSS)     ", print_generic, NULL },
  { CKA_NSS_TRUST_DIGITAL_SIGNATURE, "CKA_NSS_TRUST_DIGITAL_SIGNATURE(NSS)   ", print_boolean, NULL },
  { CKA_NSS_TRUST_NON_REPUDIATION, "CKA_TRUST_NON_REPUDIATION(NSS)       ", print_boolean, NULL },
  { CKA_NSS_TRUST_KEY_ENCIPHERMENT, "CKA_TRUST_KEY_ENCIPHERMENT(NSS)     ", print_boolean, NULL },
  { CKA_NSS_TRUST_DATA_ENCIPHERMENT, "CKA_TRUST_DATA_ENCIPHERMENT(NSS)   ", print_boolean, NULL },
  { CKA_NSS_TRUST_KEY_AGREEMENT, "CKA_TRUST_KEY_AGREEMENT(NSS)           ", print_boolean, NULL },
  { CKA_NSS_TRUST_KEY_CERT_SIGN, "CKA_TRUST_KEY_CERT_SIGN(NSS)           ", print_boolean, NULL },
  { CKA_NSS_TRUST_CRL_SIGN, "CKA_TRUST_CRL_SIGN(NSS)                     ", print_boolean, NULL },
  { CKA_NSS_TRUST_SERVER_AUTH, "CKA_TRUST_SERVER_AUTH(NSS)               ", print_boolean, NULL },
  { CKA_NSS_TRUST_CLIENT_AUTH, "CKA_TRUST_CLIENT_AUTH(NSS)               ", print_boolean, NULL },
  { CKA_NSS_TRUST_CODE_SIGNING, "CKA_TRUST_CODE_SIGNING(NSS)             ", print_boolean, NULL },
  { CKA_NSS_TRUST_EMAIL_PROTECTION, "CKA_TRUST_EMAIL_PROTECTION(NSS)     ", print_boolean, NULL },
  { CKA_NSS_TRUST_IPSEC_END_SYSTEM, "CKA_TRUST_IPSEC_END_SYSTEM(NSS)     ", print_boolean, NULL },
  { CKA_NSS_TRUST_IPSEC_TUNNEL, "CKA_TRUST_IPSEC_TUNNEL(NSS)             ", print_boolean, NULL },
  { CKA_NSS_TRUST_IPSEC_USER, "CKA_TRUST_IPSEC_USER(NSS)                 ", print_boolean, NULL },
  { CKA_NSS_TRUST_TIME_STAMPING, "CKA_TRUST_TIME_STAMPING(NSS)           ", print_boolean, NULL },
  { CKA_NSS_CERT_SHA1_HASH, "CKA_CERT_SHA1_HASH(NSS)                     ", print_generic, NULL },
  { CKA_NSS_CERT_MD5_HASH, "CKA_CERT_MD5_HASH(NSS)                       ", print_generic, NULL },
};
// clang-format on

CK_ULONG ck_attribute_num = sizeof(ck_attribute_specs)/sizeof(type_spec);


const char *
lookup_enum_spec(enum_spec *spec, CK_ULONG value)
{
	CK_ULONG i;

	for(i = 0; i < spec->size; i++)
		if(spec->specs[i].type == value)
			return spec->specs[i].name;
	return NULL;
}


const char *
lookup_enum(CK_ULONG type, CK_ULONG value)
{
	CK_ULONG i;

	for(i = 0; ck_types[i].type < ( sizeof(ck_types) / sizeof(enum_spec) ) ; i++)
		if(ck_types[i].type == type)
			return lookup_enum_spec(&(ck_types[i]), value);
	return NULL;
}


void
show_error( FILE *f, char *str, CK_RV rc )
{
	fprintf(f, "%s returned:  %ld %s", str, (unsigned long) rc, lookup_enum (RV_T, rc ));
	fprintf(f, "\n");
}


void
print_ck_info(FILE *f, CK_INFO *info)
{
	fprintf(f, "      cryptokiVersion:         %d.%d\n",    info->cryptokiVersion.major, info->cryptokiVersion.minor );
	fprintf(f, "      manufacturerID:         '%32.32s'\n",  info->manufacturerID );
	fprintf(f, "      flags:                   %0lx\n",     info->flags );
	fprintf(f, "      libraryDescription:     '%32.32s'\n",  info->libraryDescription );
	fprintf(f, "      libraryVersion:          %d.%d\n",    info->libraryVersion.major, info->libraryVersion.minor );
}


void
print_slot_list(FILE *f, CK_SLOT_ID_PTR pSlotList, CK_ULONG ulCount)
{
	CK_ULONG i;

	if(pSlotList) {
		for (i = 0; i < ulCount; i++)
			fprintf(f, "Slot %ld\n", pSlotList[i]);
	}
	else {
		fprintf(f, "Count is %ld\n", ulCount);
	}
}


void
print_slot_info(FILE *f, CK_SLOT_INFO *info)
{
	size_t i;
	enum_specs ck_flags[] = {
		{ CKF_TOKEN_PRESENT    , "CKF_TOKEN_PRESENT                " },
		{ CKF_REMOVABLE_DEVICE , "CKF_REMOVABLE_DEVICE             " },
		{ CKF_HW_SLOT          , "CKF_HW_SLOT                      " },
	};

	fprintf(f, "      slotDescription:        '%32.32s'\n",  info->slotDescription );
	fprintf(f, "                              '%32.32s'\n",  info->slotDescription+32 );
	fprintf(f, "      manufacturerID:         '%32.32s'\n",  info->manufacturerID );
	fprintf(f, "      hardwareVersion:         %d.%d\n",    info->hardwareVersion.major, info->hardwareVersion.minor );
	fprintf(f, "      firmwareVersion:         %d.%d\n",    info->firmwareVersion.major, info->firmwareVersion.minor );
	fprintf(f, "      flags:                   %0lx\n",     info->flags );

	for(i = 0; i < sizeof (ck_flags) / sizeof (*ck_flags); i++)
		if(info->flags & ck_flags[i].type)
			fprintf(f, "        %s\n", ck_flags[i].name);
}


void
print_token_info(FILE *f, CK_TOKEN_INFO *info)
{
	size_t            i;
	enum_specs ck_flags[] = {
		{ CKF_RNG                          , "CKF_RNG                          " },
		{ CKF_WRITE_PROTECTED              , "CKF_WRITE_PROTECTED              " },
		{ CKF_LOGIN_REQUIRED               , "CKF_LOGIN_REQUIRED               " },
		{ CKF_USER_PIN_INITIALIZED         , "CKF_USER_PIN_INITIALIZED         " },
		{ CKF_RESTORE_KEY_NOT_NEEDED       , "CKF_RESTORE_KEY_NOT_NEEDED       " },
		{ CKF_CLOCK_ON_TOKEN               , "CKF_CLOCK_ON_TOKEN               " },
		{ CKF_PROTECTED_AUTHENTICATION_PATH, "CKF_PROTECTED_AUTHENTICATION_PATH" },
		{ CKF_DUAL_CRYPTO_OPERATIONS       , "CKF_DUAL_CRYPTO_OPERATIONS       " },
		{ CKF_TOKEN_INITIALIZED            , "CKF_TOKEN_INITIALIZED            " },
		{ CKF_SECONDARY_AUTHENTICATION     , "CKF_SECONDARY_AUTHENTICATION     " },
		{ CKF_USER_PIN_COUNT_LOW           , "CKF_USER_PIN_COUNT_LOW           " },
		{ CKF_USER_PIN_FINAL_TRY           , "CKF_USER_PIN_FINAL_TRY           " },
		{ CKF_USER_PIN_LOCKED              , "CKF_USER_PIN_LOCKED              " },
		{ CKF_USER_PIN_TO_BE_CHANGED       , "CKF_USER_PIN_TO_BE_CHANGED       " },
		{ CKF_SO_PIN_COUNT_LOW             , "CKF_SO_PIN_COUNT_LOW             " },
		{ CKF_SO_PIN_FINAL_TRY             , "CKF_SO_PIN_FINAL_TRY             " },
		{ CKF_SO_PIN_LOCKED                , "CKF_SO_PIN_LOCKED                " },
		{ CKF_SO_PIN_TO_BE_CHANGED         , "CKF_SO_PIN_TO_BE_CHANGED         " },
		{ CKF_ERROR_STATE                  , "CKF_ERROR_STATE                  " },
		{ CKF_SEED_RANDOM_REQUIRED         , "CKF_SEED_RANDOM_REQUIRED         " },
		{ CKF_ASYNC_SESSION_SUPPORTED      , "CKF_ASYNC_SESSION_SUPPORTED      " },
	};

	fprintf(f, "      label:                  '%32.32s'\n",  info->label );
	fprintf(f, "      manufacturerID:         '%32.32s'\n",  info->manufacturerID );
	fprintf(f, "      model:                  '%16.16s'\n",  info->model );
	fprintf(f, "      serialNumber:           '%16.16s'\n",  info->serialNumber );
	fprintf(f, "      ulMaxSessionCount:       %ld\n",       info->ulMaxSessionCount );
	fprintf(f, "      ulSessionCount:          %ld\n",       info->ulSessionCount );
	fprintf(f, "      ulMaxRwSessionCount:     %ld\n",       info->ulMaxRwSessionCount );
	fprintf(f, "      ulRwSessionCount:        %ld\n",       info->ulRwSessionCount );
	fprintf(f, "      ulMaxPinLen:             %ld\n",       info->ulMaxPinLen );
	fprintf(f, "      ulMinPinLen:             %ld\n",       info->ulMinPinLen );
	fprintf(f, "      ulTotalPublicMemory:     %ld\n",       info->ulTotalPublicMemory );
	fprintf(f, "      ulFreePublicMemory:      %ld\n",       info->ulFreePublicMemory );
	fprintf(f, "      ulTotalPrivateMemory:    %ld\n",       info->ulTotalPrivateMemory );
	fprintf(f, "      ulFreePrivateMemory:     %ld\n",       info->ulFreePrivateMemory );
	fprintf(f, "      hardwareVersion:         %d.%d\n",     info->hardwareVersion.major, info->hardwareVersion.minor );
	fprintf(f, "      firmwareVersion:         %d.%d\n",     info->firmwareVersion.major, info->firmwareVersion.minor );
	fprintf(f, "      time:                   '%16.16s'\n",  info->utcTime );
	fprintf(f, "      flags:                   %0lx\n",      info->flags );

	for(i = 0; i < sizeof (ck_flags) / sizeof (*ck_flags); i++)
		if(info->flags & ck_flags[i].type)
			fprintf(f, "        %s\n", ck_flags[i].name);
}


void
print_mech_list(FILE *f, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG ulMechCount)
{
	CK_ULONG          imech;

	if(pMechanismList) {
		for (imech = 0; imech < ulMechCount; imech++) {
			const char *name = lookup_enum(MEC_T, pMechanismList[imech]);
			if (name)
				fprintf(f, "%30s \n", name);
			else
				fprintf(f, " Unknown Mechanism (%08lx)  \n", pMechanismList[imech]);
		}
	}
	else {
		fprintf(f, "Count is %ld\n", ulMechCount);
	}
}


void
print_mech_info(FILE *f, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR minfo)
{
	const char *name = lookup_enum(MEC_T, type);
	CK_ULONG known_flags = CKF_HW | CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT |
			       CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY | CKF_MULTI_MESSAGE |
			       CKF_FIND_OBJECTS | CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST |
			       CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER |
			       CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_WRAP | CKF_UNWRAP |
			       CKF_DERIVE | CKF_EC_F_P | CKF_EC_F_2M | CKF_EC_ECPARAMETERS |
			       CKF_EC_OID | CKF_EC_UNCOMPRESS | CKF_EC_CURVENAME |
			       CKF_EC_NAMEDCURVE | CKF_ENCAPSULATE | CKF_DECAPSULATE;

	if (name)
		fprintf(f, "%s : ", name);
	else
		fprintf(f, "Unknown Mechanism (%08lx) : ", type);

	fprintf(f, "min:%lu max:%lu flags:0x%lX ",
			(unsigned long) minfo->ulMinKeySize,
			(unsigned long) minfo->ulMaxKeySize, minfo->flags);
	fprintf(f, "( %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s)\n",
			(minfo->flags & CKF_HW)                ? "Hardware "    : "",
			(minfo->flags & CKF_MESSAGE_ENCRYPT)   ? "MsgEncrypt "  : "",
			(minfo->flags & CKF_MESSAGE_DECRYPT)   ? "MsgDencrypt " : "",
			(minfo->flags & CKF_MESSAGE_SIGN)      ? "MsgSign "     : "",
			(minfo->flags & CKF_MESSAGE_VERIFY)    ? "MsgVerify "   : "",
			(minfo->flags & CKF_MULTI_MESSAGE)     ? "MultiMsg "    : "",
			(minfo->flags & CKF_ENCRYPT)           ? "Encrypt "     : "",
			(minfo->flags & CKF_DECRYPT)           ? "Decrypt "     : "",
			(minfo->flags & CKF_DIGEST)            ? "Digest "      : "",
			(minfo->flags & CKF_SIGN)              ? "Sign "        : "",
			(minfo->flags & CKF_SIGN_RECOVER)      ? "SigRecov "    : "",
			(minfo->flags & CKF_VERIFY)            ? "Verify "      : "",
			(minfo->flags & CKF_VERIFY_RECOVER)    ? "VerRecov "    : "",
			(minfo->flags & CKF_GENERATE)          ? "Generate "    : "",
			(minfo->flags & CKF_GENERATE_KEY_PAIR) ? "KeyPair "     : "",
			(minfo->flags & CKF_WRAP)              ? "Wrap "        : "",
			(minfo->flags & CKF_UNWRAP)            ? "Unwrap "      : "",
			(minfo->flags & CKF_DERIVE)            ? "Derive "      : "",
			(minfo->flags & CKF_EC_F_P)            ? "F(P) "        : "",
			(minfo->flags & CKF_EC_F_2M)           ? "F(2^M) "      : "",
			(minfo->flags & CKF_EC_ECPARAMETERS)   ? "EcParams "    : "",
			(minfo->flags & CKF_EC_OID)            ? "OID "         : "",
			(minfo->flags & CKF_EC_UNCOMPRESS)     ? "Uncompress "  : "",
			(minfo->flags & CKF_EC_COMPRESS)       ? "Compress "    : "",
			(minfo->flags & CKF_EC_CURVENAME)      ? "CurveName "   : "",
			(minfo->flags & CKF_EC_NAMEDCURVE)     ? "NamedCurve "  : "",
			(minfo->flags & CKF_ENCAPSULATE)       ? "Encapsulate " : "",
			(minfo->flags & CKF_DECAPSULATE)       ? "Decapsulate " : "",
			(minfo->flags & ~known_flags)          ? "Unknown "     : "");
}


void
print_attribute_list(FILE *f, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_ULONG j, k;
	CK_KEY_TYPE key_type = -1;
	int found;

	if (!pTemplate)
		return;

	/* Some attributes are key type specific -- first check if we have a key type
	 * in the template and if so, store it */
	for (j = 0; j < ulCount; j++) {
		if (pTemplate[j].type == CKA_KEY_TYPE && pTemplate[j].pValue) {
			key_type = *(CK_KEY_TYPE *)pTemplate[j].pValue;
			break;
		}
	}

	for(j = 0; j < ulCount ; j++) {
		found = 0;
		for(k = 0; k < ck_attribute_num; k++) {
			if(ck_attribute_specs[k].type == pTemplate[j].type) {
				found = 1;
				fprintf(f, "    %s ", ck_attribute_specs[k].name);
				if(pTemplate[j].pValue && ((long)pTemplate[j].ulValueLen) > 0) {
					ck_attribute_specs[k].display(
							f, pTemplate[j].type, pTemplate[j].pValue,
							pTemplate[j].ulValueLen,
							ck_attribute_specs[k].arg,
							key_type);
				} else {
					fprintf(f, "%s\n", buf_spec(pTemplate[j].pValue, pTemplate[j].ulValueLen));
				}
				k = ck_attribute_num;
			}
		}
		if (!found) {
			fprintf(f, "    CKA_? (0x%08lx)    ", pTemplate[j].type);
			fprintf(f, "%s\n", buf_spec(pTemplate[j].pValue, pTemplate[j].ulValueLen));
		}
	}
}


void
print_attribute_list_req(FILE *f, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_ULONG j, k;
	int found;

	if (!pTemplate)
		return;

	for(j = 0; j < ulCount ; j++) {
		found = 0;
		for(k = 0; k < ck_attribute_num; k++) {
			if(ck_attribute_specs[k].type == pTemplate[j].type) {
				found = 1;
				fprintf(f, "    %s ", ck_attribute_specs[k].name);
				fprintf(f, "%s\n", buf_spec(pTemplate[j].pValue, pTemplate[j].ulValueLen));
				k = ck_attribute_num;
			}
		}

		if (!found) {
			fprintf(f, "    CKA_? (0x%08lx)    ", pTemplate[j].type);
			fprintf(f, "%s\n", buf_spec(pTemplate[j].pValue, pTemplate[j].ulValueLen));
		}
	}
}


void
print_session_info(FILE *f, CK_SESSION_INFO *info)
{
	size_t i;
	enum_specs ck_flags[] = {
			{CKF_RW_SESSION     , "CKF_RW_SESSION                   "},
			{CKF_SERIAL_SESSION , "CKF_SERIAL_SESSION               "},
			{CKF_ASYNC_SESSION  , "CKF_ASYNC_SESSION                "},
	};

	fprintf(f, "      slotID:                  %ld\n",       info->slotID );
	fprintf(f, "      state:                   %0lx (%32.32s)\n", info->state, lookup_enum(STA_T, info->state));
	fprintf(f, "      flags:                   %0lx\n",     info->flags );

	for(i = 0; i < sizeof (ck_flags) / sizeof (*ck_flags); i++) {
		if(info->flags & ck_flags[i].type)
			fprintf(f, "        %s\n", ck_flags[i].name);
	}
	fprintf(f, "      ulDeviceError:           %0lx\n",     info->ulDeviceError );
}


void
print_interfaces_list(FILE *f, CK_INTERFACE_PTR pInterfacesList, CK_ULONG ulCount)
{
	CK_ULONG i;

	if (pInterfacesList) {
		for (i = 0; i < ulCount; i++) {
			CK_INTERFACE_PTR in = &pInterfacesList[i];
			fprintf(f, "Interface '%s' version=%d.%d flags=%lx\n",
					in->pInterfaceName,
					((CK_VERSION *)(in->pFunctionList))->major,
					((CK_VERSION *)(in->pFunctionList))->minor,
					in->flags);
		}
	}
	else {
		fprintf(f, "Count is %ld\n", ulCount);
	}
}
