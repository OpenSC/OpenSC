/*
 * sc-hsm-tool.c: SmartCard-HSM Management Tool
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2012 www.CardContact.de, Andreas Schwier, Minden, Germany
 * Copyright (C) 2018-2019 GSMK - Gesellschaft für Sichere Mobile Kommunikation mbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

/* Requires openssl for dkek import */
#include <openssl/opensslv.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "fread_to_eof.h"
#include "libopensc/sc-ossl-compat.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/card-sc-hsm.h"
#include "util.h"

static const char *app_name = "sc-hsm-tool";

static const char magic[] = "Salted__";

static struct sc_aid sc_hsm_aid = { { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 }, 11 };

static int	opt_wait = 0;
static char *opt_reader = NULL;
static char *opt_label = NULL;
static int	verbose = 0;

// Some reasonable maximums
#define MAX_CERT		4096
#define MAX_PRKD		256
#define MAX_KEY			1500
#define MAX_WRAPPED_KEY	(MAX_CERT + MAX_PRKD + MAX_KEY)

#define SEED_LENGTH 16

enum {
	OPT_SO_PIN = 0x100,
	OPT_PIN,
	OPT_RETRY,
	OPT_BIO1,
	OPT_BIO2,
	OPT_PASSWORD,
	OPT_PASSWORD_SHARES_THRESHOLD,
	OPT_PASSWORD_SHARES_TOTAL
};

// clang-format off
static const struct option options[] = {
	{ "initialize",				0, NULL,		'X' },
	{ "create-dkek-share",		1, NULL,		'C' },
	{ "import-dkek-share",		1, NULL,		'I' },
#ifdef PRINT_DKEK_SHARE
	{ "print-dkek-share",		1, NULL,		'P' },
#endif
	{ "wrap-key",				1, NULL,		'W' },
	{ "unwrap-key",				1, NULL,		'U' },
	{ "public-key-auth",		1, NULL,		'K' },
	{ "required-pub-keys",		1, NULL,		'n' },
	{ "export-for-pub-key-auth",1, NULL,		'e' },
	{ "register-public-key",	1, NULL,		'g' },
	{ "public-key-auth-status",	0, NULL,		'S' },
	{ "dkek-shares",			1, NULL,		's' },
	{ "so-pin",					1, NULL,		OPT_SO_PIN },
	{ "pin",					1, NULL,		OPT_PIN },
	{ "pin-retry",				1, NULL,		OPT_RETRY },
	{ "bio-server1",			1, NULL,		OPT_BIO1 },
	{ "bio-server2",			1, NULL,		OPT_BIO2 },
	{ "password",				1, NULL,		OPT_PASSWORD },
	{ "pwd-shares-threshold",	1, NULL,		OPT_PASSWORD_SHARES_THRESHOLD },
	{ "pwd-shares-total",		1, NULL,		OPT_PASSWORD_SHARES_TOTAL },
	{ "key-reference",			1, NULL,		'i' },
	{ "label",					1, NULL,		'l' },
	{ "force",					0, NULL,		'f' },
	{ "reader",					1, NULL,		'r' },
	{ "wait",					0, NULL,		'w' },
	{ "verbose",				0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};
// clang-format on

static const char *option_help[] = {
	"Initialize token",
	"Create DKEK key share and save to <filename>",
	"Import DKEK key share <filename>",
#ifdef PRINT_DKEK_SHARE
	"Print HEX of DKEK key share <filename>",
#endif
	"Wrap key and save to <filename>",
	"Unwrap key read from <filename>",
	"Use public key authentication, set total number of public keys",
	"Number of public keys required for authentication [1]",
	"Export key for public key authentication",
	"Register public key for public key authentication (PKA file)",
	"Show status of public key authentication",
	"Number of DKEK shares [No DKEK]",
	"Define security officer PIN (SO-PIN)",
	"Define user PIN",
	"Define user PIN retry counter",
	"AID of biometric server for template 1 (hex)",
	"AID of biometric server for template 2 (hex)",
	"Define password for DKEK share",
	"Define threshold for number of password shares required for reconstruction",
	"Define number of password shares",
	"Key reference for key wrap/unwrap/export",
	"Token label for --initialize",
	"Force replacement of key and certificate",
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Verbose operation, may be used several times",
};

typedef struct {
	BIGNUM * x;
	BIGNUM * y;
} secret_share_t;




/**
 * Generate a prime number
 *
 * The internal CPRNG is seeded using the provided seed value.
 *
 * @param prime Pointer for storage of prime number
 * @param s Secret to share
 * @param bits Bit size of prime
 * @param rngSeed Seed value for CPRNG
 * @param rngSeedLength Length of Seed value for CPRNG
 *
 */
static int generatePrime(BIGNUM *prime, const BIGNUM *s, const int bits, unsigned char *rngSeed, const unsigned int rngSeedLength)
{
	int max_rounds = 1000;

	// Seed the RNG
	RAND_seed(rngSeed, rngSeedLength);

	// Clear the prime value
	BN_clear(prime);

	do {
		// Generate random prime
		BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
	} while ((BN_ucmp(prime, s) == -1) && (max_rounds-- > 0));	// If prime < s or not reached 1000 tries

	if (max_rounds > 0)
		return 0;
	else
		return -1; // We could not find a prime number
}



/**
 * Helper method to calculate the y-value
 * for a given x-value and a polynomial
 *
 * @param x X-value
 * @param polynomial The underlying polynomial
 * @param t Threshold (determines the degree of the polynomial)
 * @param prime Prime for finite field arithmetic
 * @param y Pointer for storage of calculated y-value
 */
static void calculatePolynomialValue(const BIGNUM *x, BIGNUM **polynomial, const unsigned char t, const BIGNUM *prime, BIGNUM *y)
{
	BIGNUM **pp;
	BIGNUM *temp;
	BIGNUM *exponent;

	unsigned long exp;
	BN_CTX *bn_ctx;

	// Create context for temporary variables of OpenSSL engine
	bn_ctx = BN_CTX_new();

	temp = BN_new();
	exponent = BN_new();

	// Set y to ZERO
	BN_zero(y);

	/* Initialize the result using the secret value at position 0 of the polynomial */
	pp = polynomial;
	BN_copy(y, *pp);

	pp++;

	for (exp = 1; exp < t; exp++) {

		BN_copy(temp, x);

		BN_set_word(exponent, exp);
		// temp = x^exponent mod prime
		BN_mod_exp(temp, x, exponent, prime, bn_ctx);
		// exponent = temp * a = a * x^exponent mod prime
		BN_mod_mul(exponent, temp, *pp, prime, bn_ctx);
		// add the temp value from exponent to y
		BN_copy(temp, y);
		BN_mod_add(y, temp, exponent, prime, bn_ctx);
		pp++;
	}

	BN_clear_free(temp);
	BN_clear_free(exponent);

	BN_CTX_free(bn_ctx);
}



/**
 * Create shares depending on the provided parameters
 *
 * @param s Secret value to share
 * @param t Threshold needed to reconstruct the secret
 * @param n Total number of shares
 * @param prime Prime for finite field arithmetic
 * @param shares Pointer for storage of calculated shares (must be big enough to hold n shares)
 */
static int createShares(const BIGNUM *s, const unsigned char t, const unsigned char n,	const BIGNUM *prime, secret_share_t *shares)
{
	// Array representing the polynomial a(x) = s + a_1 * x + ... + a_n-1 * x^n-1 mod p
	BIGNUM **polynomial = malloc(n * sizeof(BIGNUM *));
	BIGNUM **pp;
	unsigned long i;
	secret_share_t *sp;

	if (!polynomial)
		return -1;

	// Set the secret value as the constant part of the polynomial
	pp = polynomial;
	*pp = BN_new();
	BN_copy(*pp, s);
	pp++;

	// Initialize and generate some random values for coefficients a_x in the remaining polynomial
	for (i = 1; i < t; i++) {
		*pp = BN_new();
		BN_rand_range(*pp, prime);
		pp++;
	}

	sp = shares;
	// Now calculate n secret shares
	for (i = 1; i <= n; i++) {
		sp->x = BN_new();
		sp->y = BN_new();
		BN_set_word((sp->x), i);
		calculatePolynomialValue(sp->x, polynomial, t, prime, (sp->y));
		sp++;
	}

	// Deallocate the resource of the polynomial
	pp = polynomial;
	for (i = 0; i < t; i++) {
		BN_clear_free(*pp);
		pp++;
	}

	free(polynomial);

	return 0;
}



/**
 * Reconstruct secret using the provided shares
 *
 * @param shares Shares used to reconstruct secret (should contain t entries)
 * @param t Threshold used to reconstruct the secret
 * @param prime Prime for finite field arithmetic
 * @param s Pointer for storage of calculated secret
 */
static int reconstructSecret(secret_share_t *shares, unsigned char t, const BIGNUM *prime, BIGNUM *s)
{
	unsigned char i;
	unsigned char j;

	// Array representing the polynomial a(x) = s + a_1 * x + ... + a_n-1 * x^n-1 mod p
	BIGNUM **bValue = malloc(t * sizeof(BIGNUM *));
	BIGNUM **pbValue;
	BIGNUM * numerator;
	BIGNUM * denominator;
	BIGNUM * temp;
	secret_share_t *sp_i;
	secret_share_t *sp_j;
	BN_CTX *ctx;

	if (!bValue)
		return -1;

	// Initialize
	pbValue = bValue;
	for (i = 0; i < t; i++) {
		*pbValue = BN_new();
		pbValue++;
	}

	numerator = BN_new();
	denominator = BN_new();
	temp = BN_new();

	// Create context for temporary variables of engine
	ctx = BN_CTX_new();

	pbValue = bValue;
	sp_i = shares;
	for (i = 0; i < t; i++) {

		BN_one(numerator);
		BN_one(denominator);

		sp_j = shares;

		for (j = 0; j < t; j++) {

			if (i == j) {
				sp_j++;
				continue;
			}

			BN_mul(numerator, numerator, (sp_j->x), ctx);
			BN_sub(temp, (sp_j->x), (sp_i->x));
			BN_mul(denominator, denominator, temp, ctx);

			sp_j++;
		}

		/*
		 * Use the modular inverse value of the denominator for the
		 * multiplication
		 */
		if (BN_mod_inverse(denominator, denominator, prime, ctx) == NULL ) {
			free(bValue);
			return -1;
		}

		BN_mod_mul(*pbValue, numerator, denominator, prime, ctx);

		pbValue++;
		sp_i++;
	}

	/*
	 * Calculate the secret by multiplying all y-values with their
	 * corresponding intermediate values
	 */
	pbValue = bValue;
	sp_i = shares;
	BN_zero(s);
	for (i = 0; i < t; i++) {

		BN_mul(temp, (sp_i->y), *pbValue, ctx);
		BN_add(s, s, temp);
		pbValue++;
		sp_i++;
	}

	// Perform modulo operation and copy result
	BN_nnmod(temp, s, prime, ctx);
	BN_copy(s, temp);

	BN_clear_free(numerator);
	BN_clear_free(denominator);
	BN_clear_free(temp);

	BN_CTX_free(ctx);

	// Deallocate the resource of the polynomial
	pbValue = bValue;
	for (i = 0; i < t; i++) {
		BN_clear_free(*pbValue);
		pbValue++;
	}

	free(bValue);

	return 0;
}



/**
 * Helper method to free allocated resources
 *
 * @param shares Shares to be freed
 * @param n Total number of shares to freed
 */
static int cleanUpShares(secret_share_t *shares, unsigned char n)
{
	int i;
	secret_share_t *sp;

	sp = shares;
	for (i = 0; i < n; i++) {
		BN_clear_free((sp->x));
		BN_clear_free((sp->y));
		sp++;
	}

	free(shares);

	return 0;
}



void clearScreen()
{
	if (system( "clear" )) {
		if (system( "cls" )) {
			fprintf(stderr, "Clearing the screen failed\n");
		}
	}
}



void waitForEnterKeyPressed()
{
	int c;

	fflush(stdout);
	while ((c = getchar()) != '\n' && c != EOF) {
	}
}



static void print_dkek_info(sc_cardctl_sc_hsm_dkek_t *dkekinfo)
{
	printf("DKEK shares          : %d\n", dkekinfo->dkek_shares);
	if (dkekinfo->outstanding_shares > 0) {
		printf("DKEK import pending, %d share(s) still missing\n",dkekinfo->outstanding_shares);
	} else {
		printf("DKEK key check value : ");
		util_hex_dump(stdout, dkekinfo->key_check_value, 8, NULL);
		printf("\n");
	}
}



static void print_info(sc_card_t *card, sc_file_t *file)
{
	int r, tries_left;
	struct sc_pin_cmd_data data;
	sc_cardctl_sc_hsm_dkek_t dkekinfo;

	u8 major, minor, opt;

	major = file->prop_attr[file->prop_attr_len - 2];
	minor = file->prop_attr[file->prop_attr_len - 1];
	printf("Version              : %d.%d\n", (int)major, (int)minor);

	if (file->prop_attr_len > 2) {	/* Version >= 2.0 */
		opt = file->prop_attr[file->prop_attr_len - 4];
		if (opt != 0) {
			printf("Config options       :\n");
			if (opt & INIT_RRC_ENABLED) {
				printf("  User PIN reset with SO-PIN enabled\n");
			}
			if (opt & INIT_TRANSPORT_PIN) {
				printf("  Transport-PIN mode enabled\n");
			}
		}

		/* Try to update SO-PIN info from card */
		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_GET_INFO;
		data.pin_type = SC_AC_CHV;
		data.pin_reference = ID_SO_PIN;

		r = sc_pin_cmd(card, &data, &tries_left);
		if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND) {
			printf("SmartCard-HSM has never been initialized. Please use --initialize to set SO-PIN and user PIN.\n");
		} else {
			if (tries_left == 0) {
				printf("SO-PIN locked\n");
			} else {
				printf("SO-PIN tries left    : %d\n", tries_left);
			}
			/* Try to update PIN info from card */
			memset(&data, 0, sizeof(data));
			data.cmd = SC_PIN_CMD_GET_INFO;
			data.pin_type = SC_AC_CHV;
			data.pin_reference = ID_USER_PIN;

			r = sc_pin_cmd(card, &data, &tries_left);
			if (r == SC_ERROR_CARD_CMD_FAILED) {
				printf("Public key authentication active.\n");
			} else if (r == SC_ERROR_REF_DATA_NOT_USABLE) {
				printf("Transport-PIN active. Please change to user selected PIN first.\n");
			} else {
				if (tries_left == 0) {
					printf("User PIN locked\n");
				} else {
					printf("User PIN tries left  : %d\n", tries_left);
				}
			}
		}
	} else {	/* Version < 2.0 */
		/* Try to update PIN info from card */
		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_GET_INFO;
		data.pin_type = SC_AC_CHV;
		data.pin_reference = ID_USER_PIN;

		r = sc_pin_cmd(card, &data, &tries_left);

		if (r == SC_ERROR_REF_DATA_NOT_USABLE) {
			printf("SmartCard-HSM has never been initialized. Please use --initialize to set SO-PIN and user PIN.\n");
		} else {
			if (tries_left == 0) {
				printf("User PIN locked\n");
			} else {
				printf("User PIN tries left  : %d\n", tries_left);
			}
		}
	}

	memset(&dkekinfo, 0, sizeof(dkekinfo));

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, (void *)&dkekinfo);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		return;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, *) failed with %s\n", sc_strerror(r));
	}
	print_dkek_info(&dkekinfo);
}



static int initialize(sc_card_t *card, const char *so_pin, const char *user_pin, int retry_counter, const char *bio1, const char *bio2, int dkek_shares, signed char num_of_pub_keys, u8 required_pub_keys, const char *label)
{
	sc_cardctl_sc_hsm_init_param_t param;
	size_t len;
	char *_so_pin = NULL, *_user_pin = NULL;
	int r;

	if (num_of_pub_keys != -1 && (num_of_pub_keys < 1 || num_of_pub_keys > 90)) {
		fprintf(stderr, "Total number of public keys for authentication must be between 1 and 90\n");
		return -1;
	}
	if (required_pub_keys < 1 || required_pub_keys > 90) {
		fprintf(stderr, "Number of public keys required for authentication must be between 1 and 90\n");
		return -1;
	}
	if (num_of_pub_keys != -1 && required_pub_keys > num_of_pub_keys) {
		fprintf(stderr, "Required public keys must be <= total number of public keys\n");
		return -1;
	}

	if (so_pin == NULL) {
		printf("Enter SO-PIN (16 hexadecimal characters) : ");
		util_getpass(&_so_pin, NULL, stdin);
		printf("\n");
	} else {
		_so_pin = (char *)so_pin;
	}

	len = sizeof(param.init_code);
	r = sc_hex_to_bin(_so_pin, param.init_code, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return -1;
	}

	if (len != 8) {
		fprintf(stderr, "SO-PIN must be a hexadecimal string of 16 characters\n");
		return -1;
	}

	if (user_pin == NULL) {
		printf("Enter initial User-PIN (6 - 16 characters) : ");
		util_getpass(&_user_pin, NULL, stdin);
		printf("\n");
	} else {
		_user_pin = (char *)user_pin;
	}

	param.user_pin_len = strlen(_user_pin);

	if (param.user_pin_len < 6) {
		fprintf(stderr, "PIN must be at least 6 characters long\n");
		return -1;
	}

	if (param.user_pin_len > 16) {
		fprintf(stderr, "PIN must not be longer than 16 characters\n");
		return -1;
	}

	if ((param.user_pin_len == 6) && (retry_counter > 3)) {
		fprintf(stderr, "Retry counter must not exceed 3 for a 6 digit PIN. Use a longer PIN for a higher retry counter.\n");
		return -1;
	}

	if ((param.user_pin_len == 7) && (retry_counter > 5)) {
		fprintf(stderr, "Retry counter must not exceed 5 for a 7 digit PIN. Use a longer PIN for a higher retry counter.\n");
		return -1;
	}

	if (retry_counter > 10) {
		fprintf(stderr, "Retry counter must not exceed 10\n");
		return -1;
	}

	param.user_pin = (u8 *)_user_pin;

	param.user_pin_retry_counter = (u8)retry_counter;

	if (bio1) {
		param.bio1.len = sizeof(param.bio1.value);
		r = sc_hex_to_bin(bio1, param.bio1.value, &param.bio1.len);
		if (r < 0) {
			fprintf(stderr, "Error decoding AID of biometric server for template 1 (%s)\n", sc_strerror(r));
			return -1;
		}
	} else {
		param.bio1.len = 0;
	}
	if (bio2) {
		param.bio2.len = sizeof(param.bio2.value);
		r = sc_hex_to_bin(bio2, param.bio2.value, &param.bio2.len);
		if (r < 0) {
			fprintf(stderr, "Error decoding AID of biometric server for template 2 (%s)\n", sc_strerror(r));
			return -1;
		}
	} else {
		param.bio2.len = 0;
	}

	param.options[0] = 0x00;
	param.options[1] = 0x01; /* RESET RETRY COUNTER enabled */
	if (param.bio1.len || param.bio2.len) {
		param.options[1] |= 0x04; /* Session-PIN enabled with clear on reset */
	}

	param.dkek_shares = (char)dkek_shares;
	param.num_of_pub_keys = (signed char)num_of_pub_keys; /* guaranteed in [-1,90] */
	param.required_pub_keys = (u8)required_pub_keys; /* guaranteed in [1,90] */
	param.label = (char *)label;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_INITIALIZE, (void *)&param);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_INITIALIZE, *) failed with %s\n", sc_strerror(r));
	}

	return 0;
}



static int recreate_password_from_shares(char **pwd, int *pwdlen, int num_of_password_shares)
{
	int r, i;
	BIGNUM *prime;
	BIGNUM *secret;
	BIGNUM *p;
	char inbuf[64];
	unsigned char bin[64];
	size_t binlen = 0;
	unsigned char *ip;
	secret_share_t *shares = NULL;
	secret_share_t *sp;

	if (num_of_password_shares < 2) {
		fprintf(stderr, "--pwd-shares-total must 2 or larger\n");
		return -1;
	}

	// Allocate data buffer for the shares
	shares = malloc(num_of_password_shares * sizeof(secret_share_t));
	if (!shares)
		return -1;

	/*
	 * Initialize prime and secret
	 */
	prime = BN_new();
	secret = BN_new();

	printf("\nDeciphering the DKEK for import into the SmartCard-HSM requires %i key custodians", num_of_password_shares);
	printf("\nto present their share. Only the first key custodian needs to enter the public prime.");
	printf("\nPlease remember to present the share id as well as the share value.");
	printf("\n\nPlease enter prime: ");
	memset(inbuf, 0, sizeof(inbuf));
	if (fgets(inbuf, sizeof(inbuf), stdin) == NULL) {
		fprintf(stderr, "Input aborted\n");
		free(shares);
		return -1;
	}
	binlen = 64;
	sc_hex_to_bin(inbuf, bin, &binlen);
	BN_bin2bn(bin, (int)binlen, prime);

	sp = shares;
	for (i = 0; i < num_of_password_shares; i++) {
		clearScreen();

		printf("Press <enter> to enter share %i of %i\n\n", i + 1, num_of_password_shares);
		waitForEnterKeyPressed();

		clearScreen();

		sp->x = BN_new();
		sp->y = BN_new();

		printf("Share %i of %i\n\n", i + 1, num_of_password_shares);

		printf("Please enter share ID: ");
		memset(inbuf, 0, sizeof(inbuf));
		if (fgets(inbuf, sizeof(inbuf), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			free(shares);
			return -1;
		}
		p = (sp->x);
		BN_hex2bn(&p, inbuf);

		printf("Please enter share value: ");
		memset(inbuf, 0, sizeof(inbuf));
		if (fgets(inbuf, sizeof(inbuf), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			free(shares);
			return -1;
		}
		binlen = 64;
		sc_hex_to_bin(inbuf, bin, &binlen);
		BN_bin2bn(bin, (int)binlen, (sp->y));

		sp++;
	}

	clearScreen();

	r = reconstructSecret(shares, num_of_password_shares, prime, secret);
	if (r < 0) {
		printf("\nError during reconstruction of secret. Wrong shares?\n");
		cleanUpShares(shares, num_of_password_shares);
		return r;
	}

	/*
	 * Encode the secret value
	 */
	ip = (unsigned char *) inbuf;
	*pwdlen = BN_bn2bin(secret, ip);
	*pwd = calloc(1, *pwdlen);
	if (*pwd) {
		memcpy(*pwd, ip, *pwdlen);
	}

	cleanUpShares(shares, num_of_password_shares);

	BN_clear_free(prime);
	BN_clear_free(secret);

	return *pwd ? 0 : -1;
}



static int import_dkek_share(sc_card_t *card, const char *inf, int iter, const char *password, int num_of_password_shares)
{
	sc_cardctl_sc_hsm_dkek_t dkekinfo;
	EVP_CIPHER_CTX *bn_ctx = NULL;
	FILE *in = NULL;
	u8 filebuff[64],key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH],outbuff[64];
	char *pwd = NULL;
	int r, outlen, pwdlen;

	if (inf == NULL) {
		fprintf(stderr, "No file name specified for DKEK share\n");
		return -1;
	}

	in = fopen(inf, "rb");

	if (in == NULL) {
		perror(inf);
		return -1;
	}

	if (fread(filebuff, 1, sizeof(filebuff), in) != sizeof(filebuff)) {
		perror(inf);
		fclose(in);
		return -1;
	}

	fclose(in);

	if (memcmp(filebuff, magic, sizeof(magic) - 1)) {
		fprintf(stderr, "File %s is not a DKEK share\n", inf);
		return -1;
	}

	if (password == NULL) {

		if (num_of_password_shares == -1) {
			printf("Enter password to decrypt DKEK share : ");
			util_getpass(&pwd, NULL, stdin);
			pwdlen = (int)strlen(pwd);
			printf("\n");
		} else {
			r = recreate_password_from_shares(&pwd, &pwdlen, num_of_password_shares);
			sc_log_openssl(card->ctx);
			if (r < 0) {
				return -1;
			}
		}

	} else {
		pwd = (char *) password;
		pwdlen = (int)strlen(password);
	}

	printf("Deciphering DKEK share, please wait...\n");
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), filebuff + 8, (u8 *)pwd, pwdlen, iter, key, iv);
	OPENSSL_cleanse(pwd, strlen(pwd));

	if (password == NULL) {
		free(pwd);
	}

	bn_ctx = EVP_CIPHER_CTX_new();
	if (!bn_ctx ||
			!EVP_DecryptInit_ex(bn_ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
			!EVP_DecryptUpdate(bn_ctx, outbuff, &outlen, filebuff + 16, sizeof(filebuff) - 16) ||
			!EVP_DecryptFinal_ex(bn_ctx, outbuff + outlen, &r)) {
		sc_log_openssl(card->ctx);
		EVP_CIPHER_CTX_free(bn_ctx);
		fprintf(stderr, "Error decrypting DKEK share. Password correct ?\n");
		return -1;
	}
	EVP_CIPHER_CTX_free(bn_ctx);

	memset(&dkekinfo, 0, sizeof(dkekinfo));
	memcpy(dkekinfo.dkek_share, outbuff, sizeof(dkekinfo.dkek_share));
	dkekinfo.importShare = 1;

	OPENSSL_cleanse(outbuff, sizeof(outbuff));

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, (void *)&dkekinfo);

	OPENSSL_cleanse(&dkekinfo.dkek_share, sizeof(dkekinfo.dkek_share));

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		fprintf(stderr, "Not supported by card or card not initialized for key share usage\n");
		return -1;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, *) failed with %s\n", sc_strerror(r));
		return -1;
	}
	printf("DKEK share imported\n");
	print_dkek_info(&dkekinfo);
	return 0;
}

static int print_dkek_share(sc_card_t *card, const char *inf, int iter, const char *password, int num_of_password_shares)
{
	// hex output can be used in the SCSH shell with the
	// decrypt_keyblob.js file
	sc_cardctl_sc_hsm_dkek_t dkekinfo;
	EVP_CIPHER_CTX *bn_ctx = NULL;
	FILE *in = NULL;
	u8 filebuff[64],key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH],outbuff[64];
	char *pwd = NULL;
	int r, outlen, pwdlen;
	u8 i;

	if (inf == NULL) {
		fprintf(stderr, "No file name specified for DKEK share\n");
		return -1;
	}

	in = fopen(inf, "rb");

	if (in == NULL) {
		perror(inf);
		return -1;
	}

	if (fread(filebuff, 1, sizeof(filebuff), in) != sizeof(filebuff)) {
		perror(inf);
		fclose(in);
		return -1;
	}

	fclose(in);

	if (memcmp(filebuff, magic, sizeof(magic) - 1)) {
		fprintf(stderr, "File %s is not a DKEK share\n", inf);
		return -1;
	}

	if (password == NULL) {

		if (num_of_password_shares == -1) {
			printf("Enter password to decrypt DKEK share : ");
			util_getpass(&pwd, NULL, stdin);
			pwdlen = (int)strlen(pwd);
			printf("\n");
		} else {
			r = recreate_password_from_shares(&pwd, &pwdlen, num_of_password_shares);
			if (r < 0) {
				return -1;
			}
		}

	} else {
		pwd = (char *) password;
		pwdlen = (int)strlen(password);
	}

	printf("Deciphering DKEK share, please wait...\n");
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), filebuff + 8, (u8 *)pwd, pwdlen, iter, key, iv);
	OPENSSL_cleanse(pwd, strlen(pwd));

	if (password == NULL) {
		free(pwd);
	}

	bn_ctx = EVP_CIPHER_CTX_new();
	if (!bn_ctx ||
			!EVP_DecryptInit_ex(bn_ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
			!EVP_DecryptUpdate(bn_ctx, outbuff, &outlen, filebuff + 16, sizeof(filebuff) - 16) ||
			!EVP_DecryptFinal_ex(bn_ctx, outbuff + outlen, &r)) {
		sc_log_openssl(card->ctx);
		EVP_CIPHER_CTX_free(bn_ctx);
		fprintf(stderr, "Error decrypting DKEK share. Password correct ?\n");
		return -1;
	}
	EVP_CIPHER_CTX_free(bn_ctx);

	memset(&dkekinfo, 0, sizeof(dkekinfo));
	memcpy(dkekinfo.dkek_share, outbuff, sizeof(dkekinfo.dkek_share));
	dkekinfo.importShare = 1;

	OPENSSL_cleanse(outbuff, sizeof(outbuff));

	printf("DKEK Share HEX: \n\n");

	for (i = 0; i < sizeof(dkekinfo.dkek_share); i++)
	{
	    printf("%02X", dkekinfo.dkek_share[i]);
	}
	printf("\n\n");

	OPENSSL_cleanse(&dkekinfo.dkek_share, sizeof(dkekinfo.dkek_share));

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		fprintf(stderr, "Not supported by card or card not initialized for key share usage\n");
		return -1;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, *) failed with %s\n", sc_strerror(r));
		return -1;
	}
	//printf("DKEK share imported\n");
	//print_dkek_info(&dkekinfo);
	return 0;
}

static void ask_for_password(char **pwd, int *pwdlen)
{
	char *refpwd = NULL;

	printf(	"\nThe DKEK share will be enciphered using a key derived from a user supplied password.\n");
	printf(	"The security of the DKEK share relies on a well chosen and sufficiently long password.\n");
	printf(	"The recommended length is more than 10 characters, which are mixed letters, numbers and\n");
	printf("symbols.\n\n");
	printf(	"Please keep the generated DKEK share file in a safe location. We also recommend to keep a\n");
	printf(	"paper printout, in case the electronic version becomes unavailable. A printable version\n");
	printf(	"of the file can be generated using \"openssl base64 -in <filename>\".\n");

	while (1) {
		printf("Enter password to encrypt DKEK share : ");
		util_getpass(pwd, NULL, stdin);
		printf("\n");
		if (strlen(*pwd) < 6) {
			printf("Password way to short. Please retry.\n");
			continue;
		}
		printf("Please retype password to confirm : ");
		util_getpass(&refpwd, NULL, stdin);
		printf("\n");
		if (strcmp(*pwd, refpwd)) {
			printf("Passwords do not match. Please retry.\n");
			continue;
		}
		*pwdlen = (int)strlen(*pwd);
		break;
	}

	OPENSSL_cleanse(refpwd, strlen(refpwd));
	free(refpwd);
}



static int generate_pwd_shares(sc_card_t *card, char **pwd, int *pwdlen, int password_shares_threshold, int password_shares_total)
{
	int r, i;
	BIGNUM *prime;
	BIGNUM *secret;
	unsigned char buf[64];
	char hex[64];
	int l;

	secret_share_t *shares = NULL;
	secret_share_t *sp;

	u8 rngseed[16];

	if ((password_shares_threshold == -1) || (password_shares_total == -1)) {
		fprintf(stderr, "Must specify both, --pwd-shares-total and --pwd-shares-threshold\n");
		return -1;
	}

	if (password_shares_total < 3) {
		fprintf(stderr, "--pwd-shares-total must be 3 or larger\n");
		return -1;
	}

	if (password_shares_threshold < 2) {
		fprintf(stderr, "--pwd-shares-threshold must 2 or larger\n");
		return -1;
	}

	if (password_shares_threshold > password_shares_total) {
		fprintf(stderr, "--pwd-shares-threshold must be smaller or equal to --pwd-shares-total\n");
		return -1;
	}

	printf(	"\nThe DKEK will be enciphered using a randomly generated 64 bit password.\n");
	printf(	"This password is split using a (%i-of-%i) threshold scheme.\n\n", password_shares_threshold, password_shares_total);

	printf(	"Please keep the generated and encrypted DKEK file in a safe location. We also recommend \n");
	printf(	"to keep a paper printout, in case the electronic version becomes unavailable. A printable version\n");
	printf(	"of the file can be generated using \"openssl base64 -in <filename>\".\n");

	printf("\n\nPress <enter> to continue");

	waitForEnterKeyPressed();

	*pwd = calloc(1, 8);
	*pwdlen = 8;

	r = sc_get_challenge(card, (unsigned char *)*pwd, 8);
	if (r < 0) {
		printf("Error generating random key failed with %s", sc_strerror(r));
		OPENSSL_cleanse(*pwd, *pwdlen);
		free(*pwd);
		return r;
	}
	**pwd &= 0x7F; // Make sure the bit size of the secret is not bigger than 63 bits

	/*
	 * Initialize prime and secret
	 */
	prime = BN_new();
	secret = BN_new();

	/*
	 * Encode the secret value
	 */
	BN_bin2bn((unsigned char *)*pwd, *pwdlen, secret);

	/*
	 * Generate seed and calculate a prime depending on the size of the secret
	 */
	r = sc_get_challenge(card, rngseed, SEED_LENGTH);
	if (r < 0) {
		printf("Error generating random seed failed with %s", sc_strerror(r));
		BN_clear_free(prime);
		BN_clear_free(secret);
		OPENSSL_cleanse(*pwd, *pwdlen);
		free(*pwd);
		return r;
	}

	r = generatePrime(prime, secret, 64, rngseed, SEED_LENGTH);
	if (r < 0) {
		sc_log_openssl(card->ctx);
		BN_clear_free(prime);
		BN_clear_free(secret);
		printf("Error generating valid prime number. Please try again.");
		OPENSSL_cleanse(*pwd, *pwdlen);
		free(*pwd);
		return r;
	}

	// Allocate data buffer for the generated shares
	shares = malloc(password_shares_total * sizeof(secret_share_t));

	if (!shares || 0 > createShares(secret, password_shares_threshold, password_shares_total, prime, shares)) {
		sc_log_openssl(card->ctx);
		printf("Error generating Shares. Please try again.");
		BN_clear_free(prime);
		BN_clear_free(secret);
		OPENSSL_cleanse(*pwd, *pwdlen);
		free(*pwd);
		free(shares);
		return -1;
	}

	sp = shares;
	for (i = 0; i < password_shares_total; i++) {
		clearScreen();

		printf("Press <enter> to display key share %i of %i\n\n", i + 1, password_shares_total);
		waitForEnterKeyPressed();

		clearScreen();

		printf("Share %i of %i\n\n", i + 1, password_shares_total);

		l = BN_bn2bin(prime, buf);
		sc_bin_to_hex(buf, l, hex, 64, ':');
		printf("\nPrime       : %s\n", hex);

		printf("Share ID    : %s\n", BN_bn2dec((sp->x)));
		l = BN_bn2bin((sp->y), buf);
		sc_bin_to_hex(buf, l, hex, 64, ':');
		printf("Share value : %s\n", hex);

		printf("\n\nPlease note ALL values above and press <enter> when finished");
		waitForEnterKeyPressed();

		sp++;
	}

	clearScreen();

	cleanUpShares(shares, password_shares_total);

	BN_clear_free(prime);
	BN_clear_free(secret);

	return 0;
}



static int create_dkek_share(sc_card_t *card, const char *outf, int iter, const char *password, int password_shares_threshold, int password_shares_total)
{
	EVP_CIPHER_CTX *c_ctx = NULL;
	FILE *out = NULL;
	u8 filebuff[64], key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	u8 dkek_share[32];
	char *pwd = NULL;
	int r = 0, outlen, pwdlen = 0;

	if (outf == NULL) {
		fprintf(stderr, "No file name specified for DKEK share\n");
		return -1;
	}

	if (password == NULL) {
		if ((password_shares_threshold == -1) && (password_shares_total == -1)) {
			ask_for_password(&pwd, &pwdlen);
		} else { // create password using threshold scheme
			r = generate_pwd_shares(card, &pwd, &pwdlen, password_shares_threshold, password_shares_total);
		}

	} else {
		pwd = (char *) password;
		pwdlen = (int)strlen(password);
	}

	if (r < 0) {
		fprintf(stderr, "Creating DKEK share failed\n");
		return -1;
	}

	memcpy(filebuff, magic, sizeof(magic) - 1);

	r = sc_get_challenge(card, filebuff + 8, 8);
	if (r < 0) {
		fprintf(stderr, "Error generating random number failed with %s\n", sc_strerror(r));
		return -1;
	}

	printf("Enciphering DKEK share, please wait...\n");
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), filebuff + 8, (u8 *)pwd, pwdlen, iter, key, iv);

	if (password == NULL) {
		OPENSSL_cleanse(pwd, pwdlen);
		free(pwd);
	}

	r = sc_get_challenge(card, dkek_share, sizeof(dkek_share));
	if (r < 0) {
		fprintf(stderr, "Error generating random number failed with %s\n", sc_strerror(r));
		return -1;
	}

	c_ctx = EVP_CIPHER_CTX_new();
	if (!c_ctx ||
			!EVP_EncryptInit_ex(c_ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
			!EVP_EncryptUpdate(c_ctx, filebuff + 16, &outlen, dkek_share, sizeof(dkek_share)) ||
			!EVP_EncryptFinal_ex(c_ctx, filebuff + 16 + outlen, &r)) {
		sc_log_openssl(card->ctx);
		EVP_CIPHER_CTX_free(c_ctx);
		fprintf(stderr, "Error encrypting DKEK share\n");
		return -1;
	}
	EVP_CIPHER_CTX_free(c_ctx);

	out = fopen(outf, "wb");

	if (out == NULL) {
		perror(outf);
		return -1;
	}

	if (fwrite(filebuff, 1, sizeof(filebuff), out) != sizeof(filebuff)) {
		perror(outf);
		fclose(out);
		return -1;
	}

	fclose(out);

	OPENSSL_cleanse(dkek_share, sizeof(dkek_share));

	printf("DKEK share created and saved to %s\n", outf);
	return 0;
}



static size_t determineLength(const u8 *tlv, size_t buflen)
{
	const u8 *ptr = tlv;
	unsigned int cla,tag;
	size_t len;

	if (sc_asn1_read_tag(&ptr, buflen, &cla, &tag, &len) != SC_SUCCESS
			|| ptr == NULL) {
		return 0;
	}

	return len + (ptr - tlv);
}



/**
 * Encapsulate data object as TLV object
 *
 * @param tag the one byte tag
 * @param indata the value field
 * @param inlen the length of the value field
 * @param outdata pointer to the allocated memory buffer
 * @param outlen the size of the TLV object
 */
static int wrap_with_tag(u8 tag, u8 *indata, size_t inlen, u8 **outdata, size_t *outlen)
{
	int r = sc_asn1_put_tag(tag, indata, inlen, NULL, 0, NULL);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	u8 *ptr = calloc(r, sizeof *ptr);
	if (ptr == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
	*outdata = ptr;
	*outlen = r;

	return sc_asn1_put_tag(tag, indata, inlen, *outdata, *outlen, NULL);
}



static int wrap_key(sc_context_t *ctx, sc_card_t *card, int keyid, const char *outf, const char *pin)
{
	sc_cardctl_sc_hsm_wrapped_key_t wrapped_key;
	struct sc_pin_cmd_data data;
	sc_path_t path;
	FILE *out = NULL;
	u8 fid[2];
	u8 ef_prkd[MAX_PRKD];
	u8 ef_cert[MAX_CERT];
	u8 wrapped_key_buff[MAX_KEY];
	u8 keyblob[MAX_WRAPPED_KEY];
	u8 *key;
	u8 *ptr;
	char *lpin = NULL;
	size_t key_len;
	int r, ef_prkd_len, ef_cert_len;

	if ((keyid < 1) || (keyid > 255)) {
		fprintf(stderr, "Invalid key reference (must be 0 < keyid <= 255)\n");
		return -1;
	}

	if (outf == NULL) {
		fprintf(stderr, "No file name specified for wrapped key\n");
		return -1;
	}

	if (pin == NULL) {
		printf("Enter User PIN : ");
		util_getpass(&lpin, NULL, stdin);
		printf("\n");
	} else {
		lpin = (char *)pin;
	}

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ID_USER_PIN;
	data.pin1.data = (unsigned char *)lpin;
	data.pin1.len = strlen(lpin);

	r = sc_pin_cmd(card, &data, NULL);

	if (r < 0) {
		fprintf(stderr, "PIN verification failed with %s\n", sc_strerror(r));
		return -1;
	}

	if (pin == NULL) {
		free(lpin);
	}

	wrapped_key.key_id = keyid;
	wrapped_key.wrapped_key = wrapped_key_buff;
	wrapped_key.wrapped_key_length = sizeof(wrapped_key_buff);

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_WRAP_KEY, (void *)&wrapped_key);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		fprintf(stderr, "Card not initialized for key wrap\n");
		return -1;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_WRAP_KEY, *) failed with %s\n", sc_strerror(r));
		return -1;
	}


	fid[0] = PRKD_PREFIX;
	fid[1] = (unsigned char)keyid;
	ef_prkd_len = 0;

	/* Try to select a related EF containing the PKCS#15 description of the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);

	if (r == SC_SUCCESS) {
		ef_prkd_len = sc_read_binary(card, 0, ef_prkd, sizeof(ef_prkd), 0);

		if (ef_prkd_len < 0) {
			fprintf(stderr, "Error reading PRKD file %s. Skipping.\n", sc_strerror(ef_prkd_len));
			ef_prkd_len = 0;
		} else {
			ef_prkd_len = (int)determineLength(ef_prkd, ef_prkd_len);
		}
	}

	fid[0] = EE_CERTIFICATE_PREFIX;
	fid[1] = (unsigned char)keyid;
	ef_cert_len = 0;

	/* Try to select a related EF containing the certificate for the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);

	if (r == SC_SUCCESS) {
		ef_cert_len = sc_read_binary(card, 0, ef_cert, sizeof(ef_cert), 0);

		if (ef_cert_len < 0) {
			fprintf(stderr, "Error reading certificate %s. Skipping\n", sc_strerror(ef_cert_len));
			ef_cert_len = 0;
		} else {
			ef_cert_len = (int)determineLength(ef_cert, ef_cert_len);
		}
	}

	ptr = keyblob;

	// Encode key in octet string object
	key_len = 0;
	r = wrap_with_tag(0x04, wrapped_key.wrapped_key, wrapped_key.wrapped_key_length,
						&key, &key_len);
	LOG_TEST_RET(ctx, r, "Out of memory");

	memcpy(ptr, key, key_len);
	ptr += key_len;

	free(key);
	key = NULL;
	key_len = 0;

	// Add private key description
	if (ef_prkd_len > 0) {
		memcpy(ptr, ef_prkd, ef_prkd_len);
		ptr += ef_prkd_len;
	}

	// Add certificate
	if (ef_cert_len > 0) {
		memcpy(ptr, ef_cert, ef_cert_len);
		ptr += ef_cert_len;
	}

	// Encode key, key description and certificate object in sequence
	r = wrap_with_tag(0x30, keyblob, ptr - keyblob, &key, &key_len);
	LOG_TEST_RET(ctx, r, "Out of memory");

	out = fopen(outf, "wb");

	if (out == NULL) {
		perror(outf);
		free(key);
		return -1;
	}

	if (fwrite(key, 1, key_len, out) != key_len) {
		perror(outf);
		free(key);
		fclose(out);
		return -1;
	}

	free(key);
	fclose(out);
	return 0;
}



static int update_ef(sc_card_t *card, u8 prefix, u8 id, int erase, const u8 *buf, size_t buflen)
{
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);

	r = sc_select_file(card, &path, NULL);

	if ((r == SC_SUCCESS) && erase) {
		sc_delete_file(card, &path);
		r = SC_ERROR_FILE_NOT_FOUND;
	}

	if (r == SC_ERROR_FILE_NOT_FOUND) {
		file = sc_file_new();
		file->id = (path.value[0] << 8) | path.value[1];
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = (size_t) 0;
		file->status = SC_FILE_STATUS_ACTIVATED;
		r = sc_create_file(card, file);
		sc_file_free(file);
		if (r < 0) {
			return r;
		}
	}

	r = sc_update_binary(card, 0, buf, buflen, 0);
	return r;
}



static int unwrap_key(sc_card_t *card, int keyid, const char *inf, const char *pin, int force)
{
	sc_cardctl_sc_hsm_wrapped_key_t wrapped_key;
	struct sc_pin_cmd_data data;
	u8 keyblob[MAX_WRAPPED_KEY];
	const u8 *ptr,*prkd,*cert;
	FILE *in = NULL;
	sc_path_t path;
	u8 fid[2];
	char *lpin = NULL;
	unsigned int cla, tag;
	int r;
	size_t keybloblen;
	size_t len, olen, prkd_len, cert_len;
	ssize_t sz;

	if ((keyid < 1) || (keyid > 255)) {
		fprintf(stderr, "Invalid key reference (must be 0 < keyid <= 255)\n");
		return -1;
	}

	if (inf == NULL) {
		fprintf(stderr, "No file name specified for wrapped key\n");
		return -1;
	}

	in = fopen(inf, "rb");

	if (in == NULL) {
		perror(inf);
		return -1;
	}

	sz = fread(keyblob, 1, sizeof(keyblob), in);
	fclose(in);
	if (sz < 0) {
		perror(inf);
		return -1;
	}
	keybloblen = sz;

	ptr = keyblob;
	if ((sc_asn1_read_tag(&ptr, keybloblen, &cla, &tag, &len) != SC_SUCCESS)
		   	|| ((cla & SC_ASN1_TAG_CONSTRUCTED) != SC_ASN1_TAG_CONSTRUCTED)
		   	|| (tag != SC_ASN1_TAG_SEQUENCE) ){
		fprintf(stderr, "Invalid wrapped key format (Outer sequence).\n");
		return -1;
	}

	if ((sc_asn1_read_tag(&ptr, len, &cla, &tag, &olen) != SC_SUCCESS)
		   	|| ((cla & SC_ASN1_TAG_CONSTRUCTED) == SC_ASN1_TAG_CONSTRUCTED)
		   	|| (tag != SC_ASN1_TAG_OCTET_STRING) ){
		fprintf(stderr, "Invalid wrapped key format (Key binary).\n");
		return -1;
	}

	wrapped_key.wrapped_key = (u8 *)ptr;
	wrapped_key.wrapped_key_length = olen;

	ptr += olen;
	prkd = ptr;
	prkd_len = determineLength(ptr, keybloblen - (ptr - keyblob));

	ptr += prkd_len;
	cert = ptr;
	cert_len = determineLength(ptr, keybloblen - (ptr - keyblob));

	printf("Wrapped key contains:\n");
	printf("  Key blob\n");
	if (prkd_len > 0) {
		printf("  Private Key Description (PRKD)\n");
	}
	if (cert_len > 0) {
		printf("  Certificate\n");
	}

	if ((prkd_len > 0) && !force) {
		fid[0] = PRKD_PREFIX;
		fid[1] = (unsigned char)keyid;

		/* Try to select a related EF containing the PKCS#15 description of the key */
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, NULL);

		if (r == SC_SUCCESS) {
			fprintf(stderr, "Found existing private key description in EF with fid %02x%02x. Please remove key first, select unused key reference or use --force.\n", fid[0], fid[1]);
			return -1;
		}
	}

	if ((cert_len > 0) && !force) {
		fid[0] = EE_CERTIFICATE_PREFIX;
		fid[1] = (unsigned char)keyid;

		/* Try to select a related EF containing the certificate */
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, NULL);

		if (r == SC_SUCCESS) {
			fprintf(stderr, "Found existing certificate in EF with fid %02x%02x. Please remove certificate first, select unused key reference or use --force.\n", fid[0], fid[1]);
			return -1;
		}
	}

	if (pin == NULL) {
		printf("Enter User PIN : ");
		util_getpass(&lpin, NULL, stdin);
		printf("\n");
	} else {
		lpin = (char *)pin;
	}

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ID_USER_PIN;
	data.pin1.data = (u8 *)lpin;
	data.pin1.len = strlen(lpin);

	r = sc_pin_cmd(card, &data, NULL);

	if (r < 0) {
		fprintf(stderr, "PIN verification failed with %s\n", sc_strerror(r));
		return -1;
	}

	if (pin == NULL) {
		free(lpin);
	}

	if (force) {
		fid[0] = KEY_PREFIX;
		fid[1] = keyid;

		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);
		sc_delete_file(card, &path);
	}

	wrapped_key.key_id = keyid;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_UNWRAP_KEY, (void *)&wrapped_key);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		fprintf(stderr, "Card not initialized for key wrap\n");
		return -1;
	}

	if (r == SC_ERROR_INCORRECT_PARAMETERS) {			// Not supported or not initialized for key shares
		fprintf(stderr, "Wrapped key does not match DKEK\n");
		return -1;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_UNWRAP_KEY, *) failed with %s\n", sc_strerror(r));
		return -1;
	}

	if (prkd_len > 0) {
		r = update_ef(card, PRKD_PREFIX, keyid, force, prkd, prkd_len);

		if (r < 0) {
			fprintf(stderr, "Updating private key description failed with %s\n", sc_strerror(r));
			return -1;
		}
	}

	if (cert_len > 0) {
		r = update_ef(card, EE_CERTIFICATE_PREFIX, keyid, force, cert, cert_len);

		if (r < 0) {
			fprintf(stderr, "Updating certificate failed with %s\n", sc_strerror(r));
			return -1;
		}
	}

	printf("Key successfully imported\n");
	return 0;
}


static int export_key(sc_card_t *card, int keyid, const char *outf)
{
	sc_path_t path;
	FILE *outfp = NULL;
	u8 fid[2];
	u8 ef_cert[MAX_CERT];
	u8 dev_aut_cert[MAX_CERT];
	u8 dica[MAX_CERT];
	u8 tag = SC_ASN1_TAG_CONSTRUCTED | SC_ASN1_TAG_SEQUENCE; /* 0x30 */
	int r = 0, ef_cert_len, total_certs_len;
	size_t dev_aut_cert_len, dica_len;
	u8 *data = NULL, *out = NULL, *ptr;
	size_t datalen, outlen;

	if ((keyid < 1) || (keyid > 255)) {
		fprintf(stderr, "Invalid key reference (must be 0 < keyid <= 255)\n");
		return -1;
	}

	fid[0] = EE_CERTIFICATE_PREFIX;
	fid[1] = (unsigned char)keyid;
	ef_cert_len = 0;

	/* Try to select a related EF containing the certificate for the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Wrong key reference (-i %d)? Failed to select file: %s\n", keyid, sc_strerror(r));
		return -1;
	}

	ef_cert_len = sc_read_binary(card, 0, ef_cert, sizeof(ef_cert), 0);
	if (ef_cert_len < 0) {
		fprintf(stderr, "Error reading certificate %s. Skipping\n", sc_strerror(ef_cert_len));
		ef_cert_len = 0;
	} else {
		ef_cert_len = (int)determineLength(ef_cert, ef_cert_len);
	}

	/* C_DevAut */
	fid[0] = 0x2F;
	fid[1] = 0x02;
	dev_aut_cert_len = 0;

	/* Read concatenation of both certificates */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to select certificates: %s\n", sc_strerror(r));
		return -1;
	}

	total_certs_len = sc_read_binary(card, 0, dev_aut_cert, sizeof(dev_aut_cert), 0);
	if (total_certs_len < 0) {
		fprintf(stderr, "Error reading certificate: %s\n", sc_strerror(total_certs_len));
		return -1;
	} else {
		dev_aut_cert_len = determineLength(dev_aut_cert, total_certs_len);
		dica_len = total_certs_len - dev_aut_cert_len;
		memcpy(dica, dev_aut_cert + dev_aut_cert_len, dica_len);
	}
	if (dica_len == 0) {
		fprintf(stderr, "Could not determine device issuer certificate\n");
		return -1;
	}

	if ((outfp = fopen(outf, "r"))) {
		fprintf(stderr, "Output file '%s' already exists\n", outf);
		fclose(outfp);
		return -1;
	}
	fprintf(stderr, "Warning: Device certificate chain not verified!\n");

	datalen = ef_cert_len + dev_aut_cert_len + dica_len;
	outlen = 8 + datalen;
	if (!(data = malloc(datalen))) {
		fprintf(stderr, "Malloc failed\n");
		r = -1;
		goto err;
	}
	if (!(out = malloc(outlen))) {
		fprintf(stderr, "Malloc failed\n");
		r = -1;
		goto err;
	}
	memcpy(data, ef_cert, ef_cert_len);
	memcpy(data + ef_cert_len, dev_aut_cert, dev_aut_cert_len);
	memcpy(data + ef_cert_len + dev_aut_cert_len, dica, dica_len);

	if ((r = sc_asn1_put_tag(tag, data, datalen, out, outlen, &ptr)) < 0) {
		fprintf(stderr, "Error formatting ASN1 sequence: %s\n", sc_strerror(r));
		r = -1;
		goto err;
	}
	outlen = ptr - out;

	if (!(outfp = fopen(outf, "wb"))) {
		perror(outf);
		r = -1;
		goto err;
	}

	if (fwrite(out, 1, outlen, outfp) != (size_t)outlen) {
		perror(outf);
		r = -1;
		goto err;
	}

err:
	if (outfp)
		fclose(outfp);
	if (out)
		free(out);
	if (data)
		free(data);

	return r;
}

static void print_pka_status(const sc_cardctl_sc_hsm_pka_status_t *status)
{
	printf("Number of public keys:     %d\n", status->num_total);
	printf("Missing public keys:       %d\n", status->num_missing);
	printf("Required pubkeys for auth: %d\n", status->num_required);
	printf("Authenticated public keys: %d\n", status->num_authenticated);
}

static int register_public_key(sc_context_t *ctx, sc_card_t *card, const char *inf)
{
	int r = 0;
	sc_cardctl_sc_hsm_pka_register_t pka_register;

	memset(&pka_register, 0, sizeof(pka_register));

	if (!fread_to_eof(inf, &pka_register.buf, &pka_register.buflen)) {
		r = -1;
		goto err;
	}

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_REGISTER_PUBLIC_KEY, &pka_register);
	if (r == SC_ERROR_INS_NOT_SUPPORTED) { /* Not supported or not initialized for public key registration */
		fprintf(stderr, "Card not initialized for public key registration\n");
		r = -1;
		goto err;
	}
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_REGISTER_PUBLIC_KEY, *) failed with %s\n", sc_strerror(r));
		r = -1;
		goto err;
	}

	print_pka_status(&pka_register.new_status);

	r = 0;
	/* fall-through */

err:
	free(pka_register.buf);
	pka_register.buf = NULL;
	return r;
}



static int public_key_auth_status(sc_context_t *ctx, sc_card_t *card)
{
	int r;
	sc_cardctl_sc_hsm_pka_status_t status;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_PUBLIC_KEY_AUTH_STATUS, &status);
	if (r == SC_ERROR_INS_NOT_SUPPORTED) { /* Not supported or not initialized for public key registration */
		fprintf(stderr, "Card not initialized for public key registration\n");
		return -1;
	}
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_PUBLIC_KEY_AUTH_STATUS, *) failed with %s\n", sc_strerror(r));
		return -1;
	}

	print_pka_status(&status);

	return 0;
}


int main(int argc, char *argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0;
	int do_initialize = 0;
	int do_import_dkek_share = 0;
	int do_print_dkek_share = 0;
	int do_create_dkek_share = 0;
	int do_wrap_key = 0;
	int do_unwrap_key = 0;
	int do_export_key = 0;
	int do_register_public_key = 0;
	int do_public_key_auth_status = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	const char *opt_so_pin = NULL;
	const char *opt_pin = NULL;
	const char *opt_filename = NULL;
	const char *opt_password = NULL;
	const char *opt_bio1 = NULL;
	const char *opt_bio2 = NULL;
	int opt_retry_counter = 3;
	int opt_num_of_pub_keys = -1;
	int opt_required_pub_keys = 1;
	int opt_dkek_shares = -1;
	int opt_key_reference = -1;
	int opt_password_shares_threshold = -1;
	int opt_password_shares_total = -1;
	int opt_force = 0;
	int opt_iter = 10000000;
	sc_context_param_t ctx_param;
	sc_context_t *ctx = NULL;
	sc_card_t *card = NULL;

	while (1) {
		c = getopt_long(argc, argv, "XC:I:P:W:U:K:n:e:g:Ss:i:fr:wv", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'X':
			do_initialize = 1;
			action_count++;
			break;
		case 'C':
			do_create_dkek_share = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'I':
			do_import_dkek_share = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'P':
			do_print_dkek_share = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'W':
			do_wrap_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'U':
			do_unwrap_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'K':
			opt_num_of_pub_keys = (int)atol(optarg);
			break;
		case 'n':
			opt_required_pub_keys = (int)atol(optarg);
			break;
		case 'e':
			do_export_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'g':
			do_register_public_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'S':
			do_public_key_auth_status = 1;
			action_count++;
			break;
		case OPT_PASSWORD:
			util_get_pin(optarg, &opt_password);
			break;
		case OPT_SO_PIN:
			util_get_pin(optarg, &opt_so_pin);
			break;
		case OPT_PIN:
			util_get_pin(optarg, &opt_pin);
			break;
		case OPT_RETRY:
			opt_retry_counter = (int)atol(optarg);
			break;
		case OPT_BIO1:
			opt_bio1 = optarg;
			break;
		case OPT_BIO2:
			opt_bio2 = optarg;
			break;
		case OPT_PASSWORD_SHARES_THRESHOLD:
			opt_password_shares_threshold = (int)atol(optarg);
			break;
		case OPT_PASSWORD_SHARES_TOTAL:
			opt_password_shares_total = (int)atol(optarg);
			break;
		case 's':
			opt_dkek_shares = (int)atol(optarg);
			break;
		case 'f':
			opt_force = 1;
			break;
		case 'i':
			opt_key_reference = (int)atol(optarg);
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'l':
			opt_label = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		}
	}

	if (!do_initialize && opt_num_of_pub_keys != -1) {
		fprintf(stderr, "Option -K (--public-key-auth) requires option -X\n");
		exit(1);
	}
	if (!do_initialize && opt_required_pub_keys != 1) {
		fprintf(stderr, "Option -n (--required-pub-keys) requires option -X\n");
		exit(1);
	}
	if (do_initialize && do_export_key) {
		fprintf(stderr, "Option -e (--export-for-pub-key-auth) excludes option -X\n");
		exit(1);
	}
	if (do_wrap_key && do_export_key) {
		fprintf(stderr, "Option -e (--export-for-pub-key-auth) excludes option -W\n");
		exit(1);
	}
	if (do_unwrap_key && do_export_key) {
		fprintf(stderr, "Option -e (--export-for-pub-key-auth) excludes option -U\n");
		exit(1);
	}
	if (do_export_key && opt_key_reference == -1) {
		fprintf(stderr, "Option -e (--export-for-pub-key-auth) requires option -i\n");
		exit(1);
	}
	if (do_initialize && do_register_public_key) {
		fprintf(stderr, "Option -g (--register-public-key) excludes option -X\n");
		exit(1);
	}
	if (do_wrap_key && do_register_public_key) {
		fprintf(stderr, "Option -g (--register-public-key) excludes option -W\n");
		exit(1);
	}
	if (do_unwrap_key && do_register_public_key) {
		fprintf(stderr, "Option -g (--register-public-key) excludes option -U\n");
		exit(1);
	}
	if (do_export_key && do_register_public_key) {
		fprintf(stderr, "Option -g (--register-public-key) excludes option -e\n");
		exit(1);
	}
	if (do_initialize && do_public_key_auth_status) {
		fprintf(stderr, "Option -S (--public-key-auth-status) excludes option -X\n");
		exit(1);
	}
	if (do_wrap_key && do_public_key_auth_status) {
		fprintf(stderr, "Option -S (--public-key-auth-status) excludes option -W\n");
		exit(1);
	}
	if (do_unwrap_key && do_public_key_auth_status) {
		fprintf(stderr, "Option -S (--public-key-auth-status) excludes option -U\n");
		exit(1);
	}
	if (do_export_key && do_public_key_auth_status) {
		fprintf(stderr, "Option -S (--public-key-auth-status) excludes option -e\n");
		exit(1);
	}
	if (do_register_public_key && do_public_key_auth_status) {
		fprintf(stderr, "Option -S (--public-key-auth-status) excludes option -g\n");
		exit(1);
	}

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.app_name = app_name;
	ctx_param.debug    = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		exit(1);
	}

	r = util_connect_card_ex(ctx, &card, opt_reader, opt_wait, 0);
	if (r != SC_SUCCESS) {
		if (r < 0) {
			fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(err));
		}
		goto end;
	}

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_select_file(card, &path, &file);

	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to select application: %s\n", sc_strerror(r));
		goto fail;
	}

	if (do_initialize && initialize(card, opt_so_pin, opt_pin, opt_retry_counter, opt_bio1, opt_bio2, opt_dkek_shares, opt_num_of_pub_keys, opt_required_pub_keys, opt_label))
		goto fail;

	if (do_create_dkek_share && create_dkek_share(card, opt_filename, opt_iter, opt_password, opt_password_shares_threshold, opt_password_shares_total))
		goto fail;

	if (do_import_dkek_share && import_dkek_share(card, opt_filename, opt_iter, opt_password, opt_password_shares_total))
		goto fail;

	if (do_print_dkek_share && print_dkek_share(card, opt_filename, opt_iter, opt_password, opt_password_shares_total))
		goto fail;

	if (do_wrap_key && wrap_key(ctx, card, opt_key_reference, opt_filename, opt_pin))
		goto fail;

	if (do_unwrap_key && unwrap_key(card, opt_key_reference, opt_filename, opt_pin, opt_force))
		goto fail;

	if (do_export_key && export_key(card, opt_key_reference, opt_filename))
		goto fail;

	if (do_register_public_key && register_public_key(ctx, card, opt_filename))
		goto fail;

	if (do_public_key_auth_status && public_key_auth_status(ctx, card))
		goto fail;

	if (action_count == 0) {
		print_info(card, file);
	}

	err = 0;
	goto end;
fail:
	err = 1;
end:
	sc_disconnect_card(card);
	sc_release_context(ctx);

	ERR_print_errors_fp(stderr);
	return err;
}
