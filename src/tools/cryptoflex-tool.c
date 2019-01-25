/*
 * cryptoflex-tool.c: Tool for doing various Cryptoflex related stuff
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "config.h"

#include "libopensc/sc-ossl-compat.h"
#include "libopensc/internal.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "libopensc/pkcs15.h"
#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"
#include "util.h"

static const char *app_name = "cryptoflex-tool";

static char * opt_reader = NULL;
static int opt_wait = 0;
static int opt_key_num = 1, opt_pin_num = -1;
static int verbose = 0;
static int opt_exponent = 3;
static int opt_mod_length = 1024;
static int opt_key_count = 1;
static int opt_pin_attempts = 10;
static int opt_puk_attempts = 10;

static const char *opt_appdf = NULL, *opt_prkeyf = NULL, *opt_pubkeyf = NULL;
static u8 *pincode = NULL;

static const struct option options[] = {
	{ "list-keys",		0, NULL, 		'l' },
	{ "create-key-files",	1, NULL,		'c' },
	{ "create-pin-file",	1, NULL,		'P' },
	{ "generate-key",	0, NULL,		'g' },
	{ "read-key",		0, NULL,		'R' },
	{ "verify-pin",		0, NULL,		'V' },
	{ "key-num",		1, NULL,		'k' },
	{ "app-df",		1, NULL,		'a' },
	{ "prkey-file",		1, NULL,		'p' },
	{ "pubkey-file",	1, NULL,		'u' },
	{ "exponent",		1, NULL,		'e' },
	{ "modulus-length",	1, NULL,		'm' },
	{ "reader",		1, NULL,		'r' },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Lists all keys in a public key file",
	"Creates new RSA key files for <arg> keys",
	"Creates a new CHV<arg> file",
	"Generates a new RSA key pair",
	"Reads a public key from the card",
	"Verifies CHV1 before issuing commands",
	"Selects which key number to operate on [1]",
	"Selects the DF to operate in",
	"Private key file",
	"Public key file",
	"The RSA exponent to use in key generation [3]",
	"Modulus length to use in key generation [1024]",
	"Uses reader <arg>",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

static char *getpin(const char *prompt)
{
	char *buf, pass[20];
	int i;

	printf("%s", prompt);
	fflush(stdout);
	if (fgets(pass, 20, stdin) == NULL)
		return NULL;
	for (i = 0; i < 20; i++)
		if (pass[i] == '\n')
			pass[i] = 0;
	if (strlen(pass) == 0)
		return NULL;
	buf = malloc(8);
	if (buf == NULL)
		return NULL;
	if (strlen(pass) > 8) {
		fprintf(stderr, "PIN code too long.\n");
		free(buf);
		return NULL;
	}
	memset(buf, 0, 8);
	strlcpy(buf, pass, 8);
	return buf;
}

static int verify_pin(int pin)
{
	char prompt[50];
	int r, tries_left = -1;

	if (pincode == NULL) {
		sprintf(prompt, "Please enter CHV%d: ", pin);
		pincode = (u8 *) getpin(prompt);
		if (pincode == NULL || strlen((char *) pincode) == 0)
			return -1;
	}
	if (pin != 1 && pin != 2)
		return -3;
	r = sc_verify(card, SC_AC_CHV, pin, pincode, 8, &tries_left);
	if (r) {
		memset(pincode, 0, 8);
		free(pincode);
		pincode = NULL;
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

static int select_app_df(void)
{
	sc_path_t path;
	sc_file_t *file;
	char str[80];
	int r;

	strcpy(str, "3F00");
	if (opt_appdf != NULL)
		strlcat(str, opt_appdf, sizeof str);
	sc_format_path(str, &path);
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "Unable to select application DF: %s\n", sc_strerror(r));
		return -1;
	}
	if (file->type != SC_FILE_TYPE_DF) {
		fprintf(stderr, "Selected application DF is not a DF.\n");
		return -1;
	}
	sc_file_free(file);
	if (opt_pin_num >= 0)
		return verify_pin(opt_pin_num);
	else
		return 0;
}

static void invert_buf(u8 *dest, const u8 *src, size_t c)
{
	size_t i;

	for (i = 0; i < c; i++)
		dest[i] = src[c-1-i];
}

static BIGNUM * cf2bn(const u8 *buf, size_t bufsize, BIGNUM *num)
{
	u8 tmp[512];

	invert_buf(tmp, buf, bufsize);

	return BN_bin2bn(tmp, bufsize, num);
}

static int bn2cf(const BIGNUM *num, u8 *buf)
{
	u8 tmp[512];
	int r;

	r = BN_bn2bin(num, tmp);
	if (r <= 0)
		return r;
	invert_buf(buf, tmp, r);

	return r;
}

static int parse_public_key(const u8 *key, size_t keysize, RSA *rsa)
{
	const u8 *p = key;
	BIGNUM *n, *e;
	int base;

	base = (keysize - 7) / 5;
	if (base != 32 && base != 48 && base != 64 && base != 128) {
		fprintf(stderr, "Invalid public key.\n");
		return -1;
	}
	p += 3;
	n = BN_new();
	if (n == NULL)
		return -1;
	cf2bn(p, 2 * base, n);
	p += 2 * base;
	p += base;
	p += 2 * base;
	e = BN_new();
	if (e == NULL)
		return -1;
	cf2bn(p, 4, e);
	if (RSA_set0_key(rsa, n, e, NULL) != 1)
	    return -1;
	return 0;
}

static int gen_d(RSA *rsa)
{
	BN_CTX *bnctx;
	BIGNUM *r0, *r1, *r2;
	const BIGNUM *rsa_p, *rsa_q, *rsa_n, *rsa_e, *rsa_d;
	BIGNUM *rsa_n_new, *rsa_e_new, *rsa_d_new;

	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -1;
	BN_CTX_start(bnctx);
	r0 = BN_CTX_get(bnctx);
	r1 = BN_CTX_get(bnctx);
	r2 = BN_CTX_get(bnctx);
	RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);

	BN_sub(r1, rsa_p, BN_value_one());
	BN_sub(r2, rsa_q, BN_value_one());
	BN_mul(r0, r1, r2, bnctx);
	if ((rsa_d_new = BN_mod_inverse(NULL, rsa_e, r0, bnctx)) == NULL) {
		fprintf(stderr, "BN_mod_inverse() failed.\n");
		return -1;
	}

	/* RSA_set0_key will free previous value, and replace with new value
	 * Thus the need to copy the contents of rsa_n and rsa_e
	 */
	rsa_n_new = BN_dup(rsa_n);
	rsa_e_new = BN_dup(rsa_e);
	if (RSA_set0_key(rsa, rsa_n_new, rsa_e_new, rsa_d_new) != 1)
		return -1;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	return 0;
}

static int parse_private_key(const u8 *key, size_t keysize, RSA *rsa)
{
	const u8 *p = key;
	BIGNUM *bn_p, *q, *dmp1, *dmq1, *iqmp;
	int base;

	base = (keysize - 3) / 5;
	if (base != 32 && base != 48 && base != 64 && base != 128) {
		fprintf(stderr, "Invalid private key.\n");
		return -1;
	}
	p += 3;
	bn_p = BN_new();
	if (bn_p == NULL)
		return -1;
	cf2bn(p, base, bn_p);
	p += base;

	q = BN_new();
	if (q == NULL)
		return -1;
	cf2bn(p, base, q);
	p += base;

	iqmp = BN_new();
	if (iqmp == NULL)
		return -1;
	cf2bn(p, base, iqmp);
	p += base;

	dmp1 = BN_new();
	if (dmp1 == NULL)
		return -1;
	cf2bn(p, base, dmp1);
	p += base;

	dmq1 = BN_new();
	if (dmq1 == NULL)
		return -1;
	cf2bn(p, base, dmq1);
	
	if (RSA_set0_factors(rsa, bn_p, q) != 1)
		return -1;
	if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1)
		return -1;
	if (gen_d(rsa))
		return -1;

	return 0;
}

static int read_public_key(RSA *rsa)
{
	int r;
	sc_path_t path;
	sc_file_t *file;
	u8 buf[2048], *p = buf;
	size_t bufsize, keysize;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I1012", &path);
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "Unable to select public key file: %s\n", sc_strerror(r));
		return 2;
	}
	bufsize = MIN(file->size, sizeof buf);
	sc_file_free(file);
	r = sc_read_binary(card, 0, buf, bufsize, 0);
	if (r < 0) {
		fprintf(stderr, "Unable to read public key file: %s\n", sc_strerror(r));
		return 2;
	}
	bufsize = r;
	do {
		if (bufsize < 4)
			return 3;
		keysize = (p[0] << 8) | p[1];
		if (keysize == 0)
			break;
		if (keysize < 3)
			return 3;
		if (p[2] == opt_key_num)
			break;
		p += keysize;
		bufsize -= keysize;
	} while (1);
	if (keysize == 0) {
		printf("Key number %d not found.\n", opt_key_num);
		return 2;
	}
	return parse_public_key(p, keysize, rsa);
}


static int read_private_key(RSA *rsa)
{
	int r;
	sc_path_t path;
	sc_file_t *file;
	const sc_acl_entry_t *e;

	u8 buf[2048], *p = buf;
	size_t bufsize, keysize;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I0012", &path);
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "Unable to select private key file: %s\n", sc_strerror(r));
		return 2;
	}
	e = sc_file_get_acl_entry(file, SC_AC_OP_READ);
	if (e == NULL || e->method == SC_AC_NEVER)
		return 10;
	bufsize = MIN(file->size, sizeof buf);
	sc_file_free(file);
	r = sc_read_binary(card, 0, buf, bufsize, 0);
	if (r < 0) {
		fprintf(stderr, "Unable to read private key file: %s\n", sc_strerror(r));
		return 2;
	}
	bufsize = r;
	do {
		if (bufsize < 4)
			return 3;
		keysize = (p[0] << 8) | p[1];
		if (keysize == 0)
			break;
		if (keysize < 3)
			return 3;
		if (p[2] == opt_key_num)
			break;
		p += keysize;
		bufsize -= keysize;
	} while (1);
	if (keysize == 0) {
		printf("Key number %d not found.\n", opt_key_num);
		return 2;
	}
	return parse_private_key(p, keysize, rsa);
}

static int read_key(void)
{
	RSA *rsa = RSA_new();
	u8 buf[1024], *p = buf;
	u8 b64buf[2048];
	int r;

	if (rsa == NULL)
		return -1;
	r = read_public_key(rsa);
	if (r)
		return r;
	r = i2d_RSA_PUBKEY(rsa, &p);
	if (r <= 0) {
		fprintf(stderr, "Error encoding public key.\n");
		return -1;
	}
	r = sc_base64_encode(buf, r, b64buf, sizeof(b64buf), 64);
	if (r < 0) {
		fprintf(stderr, "Error in Base64 encoding: %s\n", sc_strerror(r));
		return -1;
	}
	printf("-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n", b64buf);

	r = read_private_key(rsa);
	if (r == 10)
		return 0;
	else if (r)
		return r;
	p = buf;
	r = i2d_RSAPrivateKey(rsa, &p);
	if (r <= 0) {
		fprintf(stderr, "Error encoding private key.\n");
		return -1;
	}
	r = sc_base64_encode(buf, r, b64buf, sizeof(b64buf), 64);
	if (r < 0) {
		fprintf(stderr, "Error in Base64 encoding: %s\n", sc_strerror(r));
		return -1;
	}
	printf("-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----\n", b64buf);

	return 0;
}

static int list_keys(void)
{
	int r, idx = 0;
	sc_path_t path;
	u8 buf[2048], *p = buf;
	size_t keysize, i;
	int mod_lens[] = { 512, 768, 1024, 2048 };
	size_t sizes[] = { 167, 247, 327, 647 };

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I1012", &path);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Unable to select public key file: %s\n", sc_strerror(r));
		return 2;
	}
	do {
		int mod_len = -1;

		r = sc_read_binary(card, idx, buf, 3, 0);
		if (r < 0) {
			fprintf(stderr, "Unable to read public key file: %s\n", sc_strerror(r));
			return 2;
		}
		keysize = (p[0] << 8) | p[1];
		if (keysize == 0)
			break;
		idx += keysize;
		for (i = 0; i < sizeof(sizes)/sizeof(sizes[ 0]); i++)
			if (sizes[i] == keysize)
				mod_len = mod_lens[i];
		if (mod_len < 0)
			printf("Key %d -- unknown modulus length\n", p[2] & 0x0F);
		else
			printf("Key %d -- Modulus length %d\n", p[2] & 0x0F, mod_len);
	} while (1);
	return 0;
}

static int generate_key(void)
{
	sc_apdu_t apdu;
	u8 sbuf[4];
	u8 p2;
	int r;

	switch (opt_mod_length) {
	case 512:
		p2 = 0x40;
		break;
	case 768:
		p2 = 0x60;
		break;
	case 1024:
		p2 = 0x80;
		break;
	case 2048:
		p2 = 0x00;
		break;
	default:
		fprintf(stderr, "Invalid modulus length.\n");
		return 2;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, (u8) opt_key_num-1, p2);
	apdu.cla = 0xF0;
	apdu.lc = 4;
	apdu.datalen = 4;
	apdu.data = sbuf;
	sbuf[0] = opt_exponent & 0xFF;
	sbuf[1] = (opt_exponent >> 8) & 0xFF;
	sbuf[2] = (opt_exponent >> 16) & 0xFF;
	sbuf[3] = (opt_exponent >> 24) & 0xFF;
	r = select_app_df();
	if (r)
		return 1;
	if (verbose)
		printf("Generating key...\n");
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
		if (r == SC_ERROR_TRANSMIT_FAILED)
			fprintf(stderr, "Reader has timed out. It is still possible that the key generation has\n"
					"succeeded.\n");
		return 1;
	}
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		printf("Key generation successful.\n");
		return 0;
	}
	if (apdu.sw1 == 0x69 && apdu.sw2 == 0x82)
		fprintf(stderr, "CHV1 not verified or invalid exponent value.\n");
	else
		fprintf(stderr, "Card returned SW1=%02X, SW2=%02X.\n", apdu.sw1, apdu.sw2);
	return 1;
}

static int create_key_files(void)
{
	sc_file_t *file;
	int mod_lens[] = { 512, 768, 1024, 2048 };
	int sizes[] = { 163, 243, 323, 643 };
	int size = -1;
	int r;
	size_t i;

	for (i = 0; i < sizeof(mod_lens) / sizeof(int); i++)
		if (mod_lens[i] == opt_mod_length) {
			size = sizes[i];
			break;
		}
	if (size == -1) {
		fprintf(stderr, "Invalid modulus length.\n");
		return 1;
	}

	if (verbose)
		printf("Creating key files for %d keys.\n", opt_key_count);

	file = sc_file_new();
	if (!file) {
		fprintf(stderr, "out of memory.\n");
		return 1;
	}
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;

	file->id = 0x0012;
	file->size = opt_key_count * size + 3;
	sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
	sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_CHV, 1);
	sc_file_add_acl_entry(file, SC_AC_OP_INVALIDATE, SC_AC_CHV, 1);
	sc_file_add_acl_entry(file, SC_AC_OP_REHABILITATE, SC_AC_CHV, 1);

	if (select_app_df()) {
		sc_file_free(file);
		return 1;
	}
	r = sc_create_file(card, file);
	sc_file_free(file);
	if (r) {
		fprintf(stderr, "Unable to create private key file: %s\n", sc_strerror(r));
		return 1;
	}

	file = sc_file_new();
	if (!file) {
		fprintf(stderr, "out of memory.\n");
		return 1;
	}
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;

	file->id = 0x1012;
	file->size = opt_key_count * (size + 4) + 3;
	sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_CHV, 1);
	sc_file_add_acl_entry(file, SC_AC_OP_INVALIDATE, SC_AC_CHV, 1);
	sc_file_add_acl_entry(file, SC_AC_OP_REHABILITATE, SC_AC_CHV, 1);

	if (select_app_df()) {
		sc_file_free(file);
		return 1;
	}
	r = sc_create_file(card, file);
	sc_file_free(file);
	if (r) {
		fprintf(stderr, "Unable to create public key file: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Key files generated successfully.\n");
	return 0;
}

static int read_rsa_privkey(RSA **rsa_out)
{
	RSA *rsa = NULL;
	BIO *in = NULL;
	int r;

	in = BIO_new(BIO_s_file());
	if (opt_prkeyf == NULL) {
		fprintf(stderr, "Private key file must be set.\n");
		return 2;
	}
	r = BIO_read_filename(in, opt_prkeyf);
	if (r <= 0) {
		perror(opt_prkeyf);
		return 2;
	}
	rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
	if (rsa == NULL) {
		fprintf(stderr, "Unable to load private key.\n");
		return 2;
	}
	BIO_free(in);
	*rsa_out = rsa;
	return 0;
}

static int encode_private_key(RSA *rsa, u8 *key, size_t *keysize)
{
	u8 buf[1024], *p = buf;
	u8 bnbuf[256];
	int base = 0;
	int r;
	const BIGNUM *rsa_p, *rsa_q, *rsa_dmp1, *rsa_dmq1, *rsa_iqmp;

	switch (RSA_bits(rsa)) {
	case 512:
		base = 32;
		break;
	case 768:
		base = 48;
		break;
	case 1024:
		base = 64;
		break;
	case 2048:
		base = 128;
		break;
	}
	if (base == 0) {
		fprintf(stderr, "Key length invalid.\n");
		return 2;
	}
	*p++ = (5 * base + 3) >> 8;
	*p++ = (5 * base + 3) & 0xFF;
	*p++ = opt_key_num;

	RSA_get0_factors(rsa, &rsa_p, &rsa_q);

	r = bn2cf(rsa_p, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa_q, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

	r = bn2cf(rsa_iqmp, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa_dmp1, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa_dmq1, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	memcpy(key, buf, p - buf);
	*keysize = p - buf;

	return 0;
}

static int encode_public_key(RSA *rsa, u8 *key, size_t *keysize)
{
	u8 buf[1024], *p = buf;
	u8 bnbuf[256];
	int base = 0;
	int r;
	const BIGNUM *rsa_n, *rsa_e;

	switch (RSA_bits(rsa)) {
	case 512:
		base = 32;
		break;
	case 768:
		base = 48;
		break;
	case 1024:
		base = 64;
		break;
	case 2048:
		base = 128;
		break;
	}
	if (base == 0) {
		fprintf(stderr, "Key length invalid.\n");
		return 2;
	}
	*p++ = (5 * base + 7) >> 8;
	*p++ = (5 * base + 7) & 0xFF;
	*p++ = opt_key_num;

	RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
	r = bn2cf(rsa_n, bnbuf);
	if (r != 2*base) {
		fprintf(stderr, "Invalid public key.\n");
		return 2;
	}
	memcpy(p, bnbuf, 2*base);
	p += 2*base;

	memset(p, 0, base);
	p += base;

	memset(bnbuf, 0, 2*base);
	memcpy(p, bnbuf, 2*base);
	p += 2*base;
	r = bn2cf(rsa_e, bnbuf);
	if (r != 4) {
		fprintf(stderr, "Invalid exponent value.\n");
		return 2;
	}
	memcpy(p, bnbuf, 4);
	p += 4;

	memcpy(key, buf, p - buf);
	*keysize = p - buf;

	return 0;
}

static int update_public_key(const u8 *key, size_t keysize)
{
	int r, idx = 0;
	sc_path_t path;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I1012", &path);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Unable to select public key file: %s\n", sc_strerror(r));
		return 2;
	}
	idx = keysize * (opt_key_num-1);
	r = sc_update_binary(card, idx, key, keysize, 0);
	if (r < 0) {
		fprintf(stderr, "Unable to write public key: %s\n", sc_strerror(r));
		return 2;
	}
	return 0;
}

static int update_private_key(const u8 *key, size_t keysize)
{
	int r, idx = 0;
	sc_path_t path;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I0012", &path);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Unable to select private key file: %s\n", sc_strerror(r));
		return 2;
	}
	idx = keysize * (opt_key_num-1);
	r = sc_update_binary(card, idx, key, keysize, 0);
	if (r < 0) {
		fprintf(stderr, "Unable to write private key: %s\n", sc_strerror(r));
		return 2;
	}
	return 0;
}

static int store_key(void)
{
	u8 prv[1024], pub[1024];
	size_t prvsize, pubsize;
	int r;
	RSA *rsa;

	r = read_rsa_privkey(&rsa);
	if (r)
		return r;
	r = encode_private_key(rsa, prv, &prvsize);
	if (r)
		return r;
	r = encode_public_key(rsa, pub, &pubsize);
	if (r)
		return r;
	if (verbose)
		printf("Storing private key...\n");
	r = select_app_df();
	if (r)
		return r;
	r = update_private_key(prv, prvsize);
	if (r)
		return r;
	if (verbose)
		printf("Storing public key...\n");
	r = select_app_df();
	if (r)
		return r;
	r = update_public_key(pub, pubsize);
	if (r)
		return r;
	return 0;
}

static int create_pin_file(const sc_path_t *inpath, int chv, const char *key_id)
{
	char prompt[40], *pin, *puk;
	char buf[30], *p = buf;
	sc_path_t file_id, path;
	sc_file_t *file;
	size_t len;
	int r;

	file_id = *inpath;
	if (file_id.len < 2)
		return -1;
	if (chv == 1)
		sc_format_path("I0000", &file_id);
	else if (chv == 2)
		sc_format_path("I0100", &file_id);
	else
		return -1;
	r = sc_select_file(card, inpath, NULL);
	if (r)
		return -1;
	r = sc_select_file(card, &file_id, NULL);
	if (r == 0)
		return 0;

	sprintf(prompt, "Please enter CHV%d%s: ", chv, key_id);
	pin = getpin(prompt);
	if (pin == NULL)
		return -1;

	sprintf(prompt, "Please enter PUK for CHV%d%s: ", chv, key_id);
	puk = getpin(prompt);
	if (puk == NULL) {
		free(pin);
		return -1;
	}

	memset(p, 0xFF, 3);
	p += 3;
	memcpy(p, pin, 8);
	p += 8;
	*p++ = opt_pin_attempts;
	*p++ = opt_pin_attempts;
	memcpy(p, puk, 8);
	p += 8;
	*p++ = opt_puk_attempts;
	*p++ = opt_puk_attempts;
	len = p - buf;

	free(pin);
	free(puk);

	file = sc_file_new();
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
	if (inpath->len == 2 && inpath->value[0] == 0x3F &&
	    inpath->value[1] == 0x00)
		sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_AUT, 1);
	else
		sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_CHV, 2);

	sc_file_add_acl_entry(file, SC_AC_OP_INVALIDATE, SC_AC_AUT, 1);
	sc_file_add_acl_entry(file, SC_AC_OP_REHABILITATE, SC_AC_AUT, 1);
	file->size = len;
	file->id = (file_id.value[0] << 8) | file_id.value[1];
	r = sc_create_file(card, file);
	sc_file_free(file);
	if (r) {
		fprintf(stderr, "PIN file creation failed: %s\n", sc_strerror(r));
		return r;
	}
	path = *inpath;
	sc_append_path(&path, &file_id);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Unable to select created PIN file: %s\n", sc_strerror(r));
		return r;
	}
	r = sc_update_binary(card, 0, (const u8 *) buf, len, 0);
	if (r < 0) {
		fprintf(stderr, "Unable to update created PIN file: %s\n", sc_strerror(r));
		return r;
	}

	return 0;
}

static int create_pin(void)
{
	sc_path_t path;
	char buf[80];

	if (opt_pin_num != 1 && opt_pin_num != 2) {
		fprintf(stderr, "Invalid PIN number. Possible values: 1, 2.\n");
		return 2;
	}
	strcpy(buf, "3F00");
	if (opt_appdf != NULL)
		strlcat(buf, opt_appdf, sizeof buf);
	sc_format_path(buf, &path);

	return create_pin_file(&path, opt_pin_num, "");
}

int main(int argc, char *argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0;
	int do_read_key = 0;
	int do_generate_key = 0;
	int do_create_key_files = 0;
	int do_list_keys = 0;
	int do_store_key = 0;
	int do_create_pin_file = 0;
	sc_context_param_t ctx_param;

	while (1) {
		c = getopt_long(argc, argv, "P:Vslgc:Rk:r:p:u:e:m:vwa:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'l':
			do_list_keys = 1;
			action_count++;
			break;
		case 'P':
			do_create_pin_file = 1;
			opt_pin_num = atoi(optarg);
			action_count++;
			break;
		case 'R':
			do_read_key = 1;
			action_count++;
			break;
		case 'g':
			do_generate_key = 1;
			action_count++;
			break;
		case 'c':
			do_create_key_files = 1;
			opt_key_count = atoi(optarg);
			action_count++;
			break;
		case 's':
			do_store_key = 1;
			action_count++;
			break;
		case 'k':
			opt_key_num = atoi(optarg);
			if (opt_key_num < 1 || opt_key_num > 15) {
				fprintf(stderr, "Key number invalid.\n");
				exit(2);
			}
			break;
		case 'V':
			opt_pin_num = 1;
			break;
		case 'e':
			opt_exponent = atoi(optarg);
			break;
		case 'm':
			opt_mod_length = atoi(optarg);
			break;
		case 'p':
			opt_prkeyf = optarg;
			break;
		case 'u':
			opt_pubkeyf = optarg;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'a':
			opt_appdf = optarg;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	printf("Using card driver: %s\n", card->driver->name);

	if (do_create_pin_file) {
		if ((err = create_pin()) != 0)
			goto end;
		action_count--;
	}
	if (do_create_key_files) {
		if ((err = create_key_files()) != 0)
			goto end;
		action_count--;
	}
	if (do_generate_key) {
		if ((err = generate_key()) != 0)
			goto end;
		action_count--;
	}
	if (do_store_key) {
		if ((err = store_key()) != 0)
			goto end;
		action_count--;
	}
	if (do_list_keys) {
		if ((err = list_keys()) != 0)
			goto end;
		action_count--;
	}
	if (do_read_key) {
		if ((err = read_key()) != 0)
			goto end;
		action_count--;
	}
	if (pincode != NULL) {
		memset(pincode, 0, 8);
		free(pincode);
	}
end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
