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

#include "util.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int opt_reader = 0, opt_debug = 0;
int opt_key_num = 1, opt_pin_num = -1;
int quiet = 0;
int opt_exponent = 3;
int opt_mod_length = 1024;
int opt_key_count = 1;

const char *opt_appdf = NULL, *opt_prkeyf = NULL, *opt_pubkeyf = NULL;
unsigned char *pincode = NULL;

const struct option options[] = {
	{ "list-keys",		0, 0, 		'l' },
	{ "create-key-files",	1, 0,		'c' },
	{ "generate-key",	0, 0,		'g' },
	{ "read-key",		0, 0,		'R' },
	{ "verify-pin",		0, 0,		'v' },
	{ "key-num",		1, 0,		'k' },
	{ "app-df",		1, 0,		'a' },
	{ "prkey-file",		1, 0,		'p' },
	{ "pubkey-file",	1, 0,		'u' },
	{ "exponent",		1, 0,		'e' },
	{ "modulus-length",	1, 0,		'm' },
	{ "reader",		1, 0,		'r' },
	{ "quiet",		0, 0,		'q' },
	{ "debug",		0, 0,		'd' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Lists all keys in a public key file",
	"Creates new RSA key files for <arg> keys",
	"Generates a new RSA key pair",
	"Reads a public key from the card",
	"Verifies CHV1 before issuing commands",
	"Selects which key number to operate on [1]",
	"Selects the DF to operate in",
	"Private key file",
	"Public key file",
	"The RSA exponent to use in key generation [3]",
	"Modulus length to use in key generation [1024]",
	"Uses reader number <arg> [0]",
	"Quiet operation",
	"Debug output -- may be supplied several times",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;

int verify_pin(int pin)
{
	char *pass;
	static u8 pinbuf[8];
	char prompt[50];
	int r, type, tries_left = -1;
	
	if (pincode == NULL) {
		sprintf(prompt, "Please enter CHV%d: ", pin);
		pass = getpass(prompt);
		if (pass == NULL || strlen(pass) == 0)
			return -1;
		if (strlen(pass) > 8) {
			fprintf(stderr, "PIN code too long.\n");
			return -2;
		}
		memset(pinbuf, 0, sizeof(pinbuf));
		strncpy(pinbuf, pass, sizeof(pinbuf));
		memset(pass, 0, strlen(pass));
	}
	if (pin == 1)
		type = SC_AC_CHV1;
	else if (pin == 2)
		type = SC_AC_CHV2;
	else
		return -3;
	r = sc_verify(card, type, pin, pinbuf, sizeof(pinbuf), &tries_left);
	if (r) {
		memset(pinbuf, 0, sizeof(pinbuf));
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(r));
		return -1;
	}
	pincode = pinbuf;
	return 0;
}

int select_app_df()
{
	struct sc_path path;
	struct sc_file file;
	char str[80];
	int r;

	strcpy(str, "3F00");
	if (opt_appdf != NULL)
		strcat(str, opt_appdf);
	sc_format_path(str, &path);
	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "Unable to select application DF: %s\n", sc_strerror(r));
		return -1;
	}
	if (file.type != SC_FILE_TYPE_DF) {
		fprintf(stderr, "Selected application DF is not a DF.\n");
		return -1;
	}
	if (opt_pin_num >= 0)
		return verify_pin(opt_pin_num);
	else
		return 0;
}

void invert_buf(u8 *dest, const u8 *src, size_t c)
{
	int i;

	for (i = 0; i < c; i++)
		dest[i] = src[c-1-i];	
}

BIGNUM * cf2bn(const u8 *buf, size_t bufsize, BIGNUM *num)
{
	u8 tmp[512];
	
	invert_buf(tmp, buf, bufsize);
		
	return BN_bin2bn(tmp, bufsize, num);
}

int bn2cf(const BIGNUM *num, u8 *buf)
{
	u8 tmp[512];
	int r;

	r = BN_bn2bin(num, tmp);
	if (r <= 0)
		return r;
	invert_buf(buf, tmp, r);
	
	return r;
}

#if 0

int mont(RSA *rsa, u8 *j0)
{
	BIGNUM Ri, RR, Ni;
	BN_CTX *bn_ctx = BN_CTX_new();
	int num_bits = BN_num_bits(rsa->n);
	u8 tmp[512];

        BN_init(&Ri);
	BN_init(&RR);
	BN_init(&Ni);
	BN_zero(&RR);
	BN_set_bit(&RR, num_bits);
	if ((BN_mod_inverse(&Ri, &RR, rsa->n, bn_ctx)) == NULL) {
		fprintf(stderr, "BN_mod_inverse() failed.\n");
		return -1;
	}
	BN_lshift(&Ri, &Ri, num_bits);
	BN_sub_word(&Ri, 1);
	BN_div(&Ni, NULL, &Ri, rsa->n, bn_ctx);

	bn2cf(&Ni, tmp);
	memcpy(j0, tmp, BN_num_bytes(&Ni)/2);
	printf("Ni from SSL:\n");
	hex_dump_asc(stdout, tmp, BN_num_bytes(&Ni), -1);

	BN_free(&Ri);
	BN_free(&RR);
	BN_free(&Ni);
	return 0;
}

#endif

int parse_public_key(const u8 *key, size_t keysize, RSA *rsa)
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
	rsa->n = n;
	rsa->e = e;
	return 0;
}

int gen_d(RSA *rsa)
{
	BN_CTX *ctx, *ctx2;
	BIGNUM *r0, *r1, *r2;
	
	ctx = BN_CTX_new();
	ctx2 = BN_CTX_new();
	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	BN_sub(r1, rsa->p, BN_value_one());
	BN_sub(r2, rsa->q, BN_value_one());
	BN_mul(r0, r1, r2, ctx);
	if ((rsa->d = BN_mod_inverse(NULL, rsa->e, r0, ctx2)) == NULL) {
		fprintf(stderr, "BN_mod_inverse() failed.\n");
		return -1;
	}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_CTX_free(ctx2);
	return 0;
}

int parse_private_key(const u8 *key, size_t keysize, RSA *rsa)
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
	p += base;

	rsa->p = bn_p;
	rsa->q = q;
	rsa->dmp1 = dmp1;
	rsa->dmq1 = dmq1;
	rsa->iqmp = iqmp;
	if (gen_d(rsa))
		return -1;

	return 0;
}

int read_public_key(RSA *rsa)
{
	int r;
	struct sc_path path;
	struct sc_file file;
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
	bufsize = file.size;
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


int read_private_key(RSA *rsa)
{
	int r;
	struct sc_path path;
	struct sc_file file;
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
	if (file.acl[SC_AC_OP_READ] == SC_AC_NEVER)
		return 10;
	bufsize = file.size;
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

int read_key()
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

int list_keys()
{
	int r, i, idx = 0;
	struct sc_path path;
	struct sc_file file;
	u8 buf[2048], *p = buf;
	size_t keysize;
	int mod_lens[] = { 512, 768, 1024, 2048 };
	int sizes[] = { 167, 247, 327, 647 };

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I1012", &path);
	r = sc_select_file(card, &path, &file);
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
		for (i = 0; i < sizeof(sizes)/sizeof(int); i++)
			if (sizes[i] == keysize)
				mod_len = mod_lens[i];
		if (mod_len < 0)
			printf("Key %d -- unknown modulus length\n", p[2] & 0x0F);
		else
			printf("Key %d -- Modulus length %d\n", p[2] & 0x0F, mod_len);
	} while (1);
	return 0;
}

int generate_key()
{
	struct sc_apdu apdu;
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
	if (!quiet)
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

int create_key_files()
{
	struct sc_file file;
	int mod_lens[] = { 512, 768, 1024, 2048 };
	int sizes[] = { 163, 243, 323, 643 };
	int size = -1;
	int i, r;
	
	for (i = 0; i < sizeof(mod_lens) / sizeof(int); i++)
		if (mod_lens[i] == opt_mod_length) {
			size = sizes[i];
			break;
		}
	if (size == -1) {
		fprintf(stderr, "Invalid modulus length.\n");
		return 1;
	}
	
	if (!quiet)
		printf("Creating key files for %d keys.\n", opt_key_count);
	
	memset(&file, 0, sizeof(file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		file.acl[i] = SC_AC_NONE;
	file.type = SC_FILE_TYPE_WORKING_EF;
	file.ef_structure = SC_FILE_EF_TRANSPARENT;

	file.id = 0x0012;
	file.size = opt_key_count * size + 3;
	file.acl[SC_AC_OP_READ] = SC_AC_NEVER;
/*	file.acl[SC_AC_OP_READ] = SC_AC_NONE; */
	file.acl[SC_AC_OP_UPDATE] = SC_AC_CHV1;
	file.acl[SC_AC_OP_INVALIDATE] = SC_AC_CHV1;
	file.acl[SC_AC_OP_REHABILITATE] = SC_AC_CHV1;
	
	if (select_app_df())
		return 1;
	r = sc_create_file(card, &file);	
	if (r) {
		fprintf(stderr, "Unable to create private key file: %s\n", sc_strerror(r));
		return 1;
	}
	file.id = 0x1012;
	file.size = opt_key_count * (size + 4) + 3;
	file.acl[SC_AC_OP_READ] = SC_AC_NONE;
	file.acl[SC_AC_OP_UPDATE] = SC_AC_CHV1;
	file.acl[SC_AC_OP_INVALIDATE] = SC_AC_CHV1;
	file.acl[SC_AC_OP_REHABILITATE] = SC_AC_CHV1;
	if (select_app_df())
		return 1;
	r = sc_create_file(card, &file);
	if (r) {
		fprintf(stderr, "Unable to create public key file: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Key files generated successfully.\n");	
	return 0;
}

int read_rsa_privkey(RSA **rsa_out)
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

int encode_private_key(RSA *rsa, u8 *key, size_t *keysize)
{
	u8 buf[512], *p = buf;
	u8 bnbuf[256];
	int base = 0;
	int r;
	
	switch (BN_num_bits(rsa->n)) {
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
	r = bn2cf(rsa->p, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa->q, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa->iqmp, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa->dmp1, bnbuf);
	if (r != base) {
		fprintf(stderr, "Invalid private key.\n");
		return 2;
	}
	memcpy(p, bnbuf, base);
	p += base;

	r = bn2cf(rsa->dmq1, bnbuf);
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

int encode_public_key(RSA *rsa, u8 *key, size_t *keysize)
{
	u8 buf[512], *p = buf;
	u8 bnbuf[256];
	int base = 0;
	int r;
	
	switch (BN_num_bits(rsa->n)) {
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
	r = bn2cf(rsa->n, bnbuf);
	if (r != 2*base) {
		fprintf(stderr, "Invalid public key.\n");
		return 2;
	}
	memcpy(p, bnbuf, 2*base);
	p += 2*base;

#if 0
	mont(rsa, p);	/* j0 */
#else
	memset(p, 0, base);
#endif
	p += base;

	memset(bnbuf, 0, 2*base);
	memcpy(p, bnbuf, 2*base);
	p += 2*base;
	r = bn2cf(rsa->e, bnbuf);
	memcpy(p, bnbuf, 4);
	p += 4;

	memcpy(key, buf, p - buf);
	*keysize = p - buf;

	return 0;
}

int update_public_key(const u8 *key, size_t keysize)
{
	int r, idx = 0;
	struct sc_path path;
	struct sc_file file;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I1012", &path);
	r = sc_select_file(card, &path, &file);
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

int update_private_key(const u8 *key, size_t keysize)
{
	int r, idx = 0;
	struct sc_path path;
	struct sc_file file;

	r = select_app_df();
	if (r)
		return 1;
	sc_format_path("I0012", &path);
	r = sc_select_file(card, &path, &file);
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

int store_key()
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
	if (!quiet)
		printf("Storing private key...\n");
	r = select_app_df();
	if (r)
		return r;
	r = update_private_key(prv, prvsize);
	if (r)
		return r;
	if (!quiet)
		printf("Storing public key...\n");
	r = select_app_df();
	if (r)
		return r;
	r = update_public_key(pub, pubsize);
	if (r)
		return r;
	return 0;	
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0;
	int do_read_key = 0;
	int do_generate_key = 0;
	int do_create_key_files = 0;
	int do_list_keys = 0;
	int do_store_key = 0;

	while (1) {
		c = getopt_long(argc, argv, "vslgc:Rk:r:p:u:e:m:dqa:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			print_usage_and_die("cryptoflex-tool");
		switch (c) {
		case 'l':
			do_list_keys = 1;
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
		case 'v':
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
			opt_reader = atoi(optarg);
			break;
		case 'q':
			quiet++;
			break;
		case 'd':
			opt_debug++;
			break;
		case 'a':
			opt_appdf = optarg;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die("cryptoflex-tool");
	r = sc_establish_context(&ctx);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	ctx->use_std_output = 1;
	ctx->debug = opt_debug;
	if (opt_reader >= ctx->reader_count || opt_reader < 0) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		err = 1;
		goto end;
	}
	if (sc_detect_card(ctx, opt_reader) != 1) {
		fprintf(stderr, "Card not present.\n");
		err = 3;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Connecting to card in reader %s...\n", ctx->readers[opt_reader]);
	r = sc_connect_card(ctx, opt_reader, &card);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	printf("Using card driver: %s\n", card->driver->name);
	r = sc_lock(card);
	if (r) {
		fprintf(stderr, "Unable to lock card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
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
	if (pincode != NULL)
		memset(pincode, 0, 8);
end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_destroy_context(ctx);
	return err;
}
