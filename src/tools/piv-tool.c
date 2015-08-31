/*
 * piv-tool.c: Tool for accessing smart cards with libopensc
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2010 Douglas E. Engert <deengert@anl.gov>
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

/* Module only built if OPENSSL is enabled */
#include <openssl/opensslconf.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC)
#include <openssl/ec.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "util.h"

static const char *app_name = "piv-tool";

static int	opt_wait = 0;
static char **	opt_apdus;
static char *	opt_reader;
static int	opt_apdu_count = 0;
static int	verbose = 0;

enum {
	OPT_SERIAL = 0x100,
};

static const struct option options[] = {
	{ "serial",		0, NULL,	OPT_SERIAL  },
	{ "name",		0, NULL,		'n' },
	{ "admin",		1, NULL, 		'A' },
	{ "genkey",		1, NULL,		'G' },
	{ "object",		1, NULL,		'O' },
	{ "cert",		1, NULL,		'C' },
	{ "compresscert",	1, NULL,		'Z' },
	{ "out",		1, NULL, 		'o' },
	{ "in",			1, NULL, 		'i' },
	{ "send-apdu",		1, NULL,		's' },
	{ "reader",		1, NULL,		'r' },
	{ "card-driver",	1, NULL,		'c' },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Prints the card serial number",
	"Identify the card and print its name",
	"authenticate using default 3des key",
	"Generate key <ref>:<alg> 9A:06 on card, and output pubkey",
	"Load an object <containerID> containerID as defined in 800-73 without leading 0x",
	"Load a cert <ref> where <ref> is 9A,9C,9D or 9E",
	"Load a cert that has been gziped <ref>",
	"Output file for cert or key",
	"Inout file for cert",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static BIO * bp = NULL;
static EVP_PKEY * evpkey = NULL;

static int load_object(const char * object_id, const char * object_file)
{
	FILE *fp;
	sc_path_t path;
	size_t derlen;
	u8 *der = NULL;
	u8 *body;
	size_t bodylen;
	int r;
	struct stat stat_buf;

    if(!object_file || (fp=fopen(object_file, "r")) == NULL){
        printf("Cannot open object file, %s %s\n",
			(object_file)?object_file:"", strerror(errno));
        return -1;
    }

	if (0 != stat(object_file, &stat_buf)) {
		printf("unable to read file %s\n",object_file);
		return -1;
	}
	derlen = stat_buf.st_size;
	der = malloc(derlen);
	if (der == NULL) {
		printf("file %s is too big, %lu\n",
		object_file, (unsigned long)derlen);
		return-1 ;
	}
	if (1 != fread(der, derlen, 1, fp)) {
		printf("unable to read file %s\n",object_file);
		return -1;
	}
	/* check if tag and length are valid */
	body = (u8 *)sc_asn1_find_tag(card->ctx, der, derlen, 0x53, &bodylen);
	if (body == NULL || derlen != body  - der +  bodylen) {
		fprintf(stderr, "object tag or length not valid\n");
		return -1;
	}

	sc_format_path(object_id, &path);

	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "select file failed\n");
		return -1;
	}
	/* leave 8 bits for flags, and pass in total length */
	r = sc_write_binary(card, 0, der, derlen, derlen<<8);

	return r;
}


static int load_cert(const char * cert_id, const char * cert_file,
					int compress)
{
	X509 * cert = NULL;
	FILE *fp;
	u8 buf[1];
	size_t buflen = 1;
	sc_path_t path;
	u8 *der = NULL;
	u8 *p;
	size_t derlen;
	int r;

	if (!cert_file) {
        printf("Missing cert file\n");
		return -1;
	}

    if((fp=fopen(cert_file, "r"))==NULL){
        printf("Cannot open cert file, %s %s\n",
				cert_file, strerror(errno));
        return -1;
    }
	if (compress) { /* file is gziped already */
		struct stat stat_buf;

		if (0 != stat(cert_file, &stat_buf)) {
			printf("unable to read file %s\n",cert_file);
			return -1;
		}
		derlen = stat_buf.st_size;
		der = malloc(derlen);
		if (der == NULL) {
			printf("file %s is too big, %lu\n",
				cert_file, (unsigned long)derlen);
			return -1 ;
		}
		if (1 != fread(der, derlen, 1, fp)) {
			printf("unable to read file %s\n",cert_file);
			return -1;
		}
	} else {
		cert = PEM_read_X509(fp, &cert, NULL, NULL);
    	if(cert == NULL){
        	printf("file %s does not conatin PEM-encoded certificate\n",
				 cert_file);
        	return -1 ;
    	}

		derlen = i2d_X509(cert, NULL);
		der = malloc(derlen);
		p = der;
		i2d_X509(cert, &p);
	}
    fclose(fp);
	sc_hex_to_bin(cert_id, buf,&buflen);

	switch (buf[0]) {
		case 0x9a: sc_format_path("0101",&path); break;
		case 0x9c: sc_format_path("0100",&path); break;
		case 0x9d: sc_format_path("0102",&path); break;
		case 0x9e: sc_format_path("0500",&path); break;
		default:
			fprintf(stderr,"cert must be 9A, 9C, 9D or 9E\n");
			return 2;
	}

	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "select file failed\n");
		 return -1;
	}
	/* we pass length  and  8 bits of flag to card-piv.c write_binary */
	/* pass in its a cert and if needs compress */
	r = sc_write_binary(card, 0, der, derlen, (derlen<<8) | (compress<<4) | 1);

	return r;

}
static int admin_mode(const char* admin_info)
{
	int r;
	u8 opts[3];
	size_t buflen = 2;


	if (strlen(admin_info) == 7 &&
			(admin_info[0] == 'A' || admin_info[0] == 'M') &&
			admin_info[1] == ':' &&
			(sc_hex_to_bin(admin_info+2, opts+1, &buflen) == 0) &&
			buflen == 2) {
		opts[0] = admin_info[0];

	} else {
		fprintf(stderr, " admin_mode params <M|A>:<keyref>:<alg>\n");
		return -1;
	}

	r = sc_card_ctl(card, SC_CARDCTL_PIV_AUTHENTICATE, &opts);
	if (r)
		fprintf(stderr, " admin_mode failed %d\n", r);
	return r;
}

/* generate a new key pair, and save public key in newkey */
static int gen_key(const char * key_info)
{
	int r;
	u8 buf[2];
	size_t buflen = 2;
	sc_cardctl_piv_genkey_info_t
		keydata = {0, 0, 0, 0, NULL, 0, NULL, 0, NULL, 0};
	unsigned long expl;
	u8 expc[4];
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC)
	int nid = -1;
#endif
	sc_hex_to_bin(key_info, buf, &buflen);
	if (buflen != 2) {
		fprintf(stderr, "<keyref>:<algid> invalid, example: 9A:06\n");
		return 2;
	}
	switch (buf[0]) {
		case 0x9a:
		case 0x9c:
		case 0x9d:
		case 0x9e:
			keydata.key_num = buf[0];
			break;
		default:
			fprintf(stderr, "<keyref>:<algid> must be 9A, 9C, 9D or 9E\n");
			return 2;
	}

	switch (buf[1]) {
		case 0x05: keydata.key_bits = 3072; break;
		case 0x06: keydata.key_bits = 1024; break;
		case 0x07: keydata.key_bits = 2048; break;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC)
		case 0x11: keydata.key_bits = 0;
			nid = NID_X9_62_prime256v1; /* We only support one curve per algid */
			break;
		case 0x14: keydata.key_bits = 0;
			nid = NID_secp384r1;
			break;
#endif
		default:
			fprintf(stderr, "<keyref>:<algid> algid=RSA - 05, 06, 07 for 3072, 1024, 2048;EC - 11, 14 for 256, 384\n");
			return 2;
	}

	keydata.key_algid = buf[1];


	r = sc_card_ctl(card, SC_CARDCTL_PIV_GENERATE_KEY, &keydata);
	if (r) {
		fprintf(stderr, "gen_key failed %d\n", r);
		return r;
	}

		evpkey = EVP_PKEY_new();

	if (keydata.key_bits > 0) { /* RSA key */
		RSA * newkey = NULL;

		newkey = RSA_new();
		if (newkey == NULL) {
			fprintf(stderr, "gen_key RSA_new failed %d\n",r);
			return -1;
		}
		newkey->n = BN_bin2bn(keydata.pubkey, keydata.pubkey_len, newkey->n);
		expl = keydata.exponent;
		expc[3] = (u8) expl & 0xff;
		expc[2] = (u8) (expl >>8) & 0xff;
		expc[1] = (u8) (expl >>16) & 0xff;
		expc[0] = (u8) (expl >>24) & 0xff;
		newkey->e =  BN_bin2bn(expc, 4,  newkey->e);

		if (verbose)
			RSA_print_fp(stdout, newkey,0);

		EVP_PKEY_assign_RSA(evpkey, newkey);

	} else { /* EC key */
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC)
		int i;
		BIGNUM *x;
		BIGNUM *y;
		EC_KEY * eckey = NULL;
		EC_GROUP * ecgroup = NULL;
		EC_POINT * ecpoint = NULL;

		ecgroup = EC_GROUP_new_by_curve_name(nid);
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
		ecpoint = EC_POINT_new(ecgroup);

		/* PIV returns 04||x||y  and x and y are the same size */
		i = (keydata.ecpoint_len - 1)/2;
		x = BN_bin2bn(keydata.ecpoint + 1, i, NULL);
		y = BN_bin2bn(keydata.ecpoint + 1 + i, i, NULL) ;
		r = EC_POINT_set_affine_coordinates_GFp(ecgroup, ecpoint, x, y, NULL);
		eckey = EC_KEY_new();
		r = EC_KEY_set_group(eckey, ecgroup);
		r = EC_KEY_set_public_key(eckey, ecpoint);

		if (verbose)
			EC_KEY_print_fp(stdout, eckey, 0);

		EVP_PKEY_assign_EC_KEY(evpkey, eckey);
#else
		fprintf(stderr, "This build of OpenSSL does not support EC keys\n");
		r = 1;
#endif /* OPENSSL_NO_EC */

	}
	if (bp)
		r = i2d_PUBKEY_bio(bp, evpkey);

	if (evpkey)
		EVP_PKEY_free(evpkey);

	return r;
}


static int send_apdu(void)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE+3];
	u8 rbuf[8192];
	size_t len0, r;
	int c;

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);

		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
			return 2;
		}

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		printf("Sending: ");
		for (r = 0; r < len0; r++)
			printf("%02X ", buf[r]);
		printf("\n");
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
			return 1;
		}
		printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
		       apdu.resplen ? ":" : "");
		if (apdu.resplen)
			util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}
	return 0;
}

static void print_serial(sc_card_t *in_card)
{
	int r;
	sc_serial_number_t serial;

	r = sc_card_ctl(in_card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r < 0)
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GET_SERIALNR, *) failed %d\n", r);
	else
		util_hex_dump_asc(stdout, serial.value, serial.len, -1);
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_send_apdu = 0;
	int do_admin_mode = 0;
	int do_gen_key = 0;
	int do_load_cert = 0;
	int do_load_object = 0;
	int compress_cert = 0;
	int do_print_serial = 0;
	int do_print_name = 0;
	int action_count = 0;
	const char *opt_driver = NULL;
	const char *out_file = NULL;
	const char *in_file = NULL;
	const char *cert_id = NULL;
	const char *object_id = NULL;
	const char *key_info = NULL;
	const char *admin_info = NULL;
	sc_context_param_t ctx_param;

	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "nA:G:O:Z:C:i:o:fvs:c:w", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case OPT_SERIAL:
			do_print_serial = 1;
			action_count++;
			break;
		case 's':
			opt_apdus = (char **) realloc(opt_apdus,
					(opt_apdu_count + 1) * sizeof(char *));
			opt_apdus[opt_apdu_count] = optarg;
			do_send_apdu++;
			if (opt_apdu_count == 0)
				action_count++;
			opt_apdu_count++;
			break;
		case 'n':
			do_print_name = 1;
			action_count++;
			break;
		case 'A':
			do_admin_mode = 1;
			admin_info = optarg;
			action_count++;
			break;
		case 'G':
			do_gen_key = 1;
			key_info = optarg;
			action_count++;
			break;
		case 'O':
			do_load_object = 1;
			object_id = optarg;
			action_count++;
			break;
		case 'Z':
			compress_cert = 1;
			/* fall through */
		case 'C':
			do_load_cert = 1;
			cert_id = optarg;
			action_count++;
			break;
		case 'i':
			in_file = optarg;
			break;
		case 'o':
			out_file = optarg;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();


	if (out_file) {
		bp = BIO_new(BIO_s_file());
		BIO_write_filename(bp, (char *)out_file);
	} else {
		bp = BIO_new(BIO_s_file());
		BIO_set_fp(bp,stdout,BIO_NOCLOSE);
	}

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	/* Only change if not in opensc.conf */
	if (verbose > 1 && ctx->debug == 0) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	if (action_count <= 0)
		goto end;

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n", opt_driver);
			err = 1;
			goto end;
		}
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (err)
		goto end;

	if (do_admin_mode) {
		if ((err = admin_mode(admin_info)))
			goto end;
		action_count--;
	}
	if (do_send_apdu) {   /* can use pin before load cert for a beta card */
		if ((err = send_apdu()))
			goto end;
		action_count--;
	}
	if (do_gen_key) {
		if ((err = gen_key(key_info)))
			goto end;
		action_count--;
	}
	if (do_load_object) {
		if ((err = load_object(object_id, in_file)))
			goto end;
		action_count--;
	}
	if (do_load_cert) {
		if ((err = load_cert(cert_id, in_file, compress_cert)))
			goto end;
		action_count--;
	}
	if (do_print_serial) {
		if (verbose)
			printf("Card serial number:");
		print_serial(card);
		action_count--;
	}
	if (do_print_name) {
		if (verbose)
			printf("Card name: ");
		printf("%s\n", card->name);
		action_count--;
	}
end:
	if (bp)
		BIO_free(bp);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);

	ERR_print_errors_fp(stderr);
	return err;
}
