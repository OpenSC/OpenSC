/*
 * piv-tool.c: Tool for accessing smart cards with libopensc
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005, Douglas E. Engert <deengert@anl.gov>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include "util.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static const char *app_name = "piv-tool";

static int	opt_reader = -1,
		opt_wait = 0;
static char **	opt_apdus;
static int	opt_apdu_count = 0;
static int	verbose = 0;

enum {
	OPT_SERIAL = 0x100,
};

static const struct option options[] = {
	{ "serial",		0, NULL,	OPT_SERIAL  },
	{ "name",		0, NULL,		'n' },
	{ "admin",		0, NULL, 		'A' },
	{ "usepin",		0, NULL,		'P' }, /* some beta cards want user pin for put_data */
	{ "genkey",		0, NULL,		'G' },
	{ "cert",		0, NULL,		'C' },
	{ "compresscert", 0, NULL,		'Z' },
	{ "req",		0, NULL, 		'R' },
	{ "out",	0, NULL, 		'o' },
	{ "in",		0, NULL, 		'o' },
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
	"authenticate using user pin", 
	"Generate key <ref>:<alg> 9A:06 on card, and output pubkey",
	"Load a cert <ref> where <ref> is 9A,9B,9C or 9D",
	"Load a cert that has been gziped <ref>",
	"Generate a cert req",
	"Output file for cert or key or req",
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
static RSA * newkey = NULL;


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

    if((fp=fopen(cert_file, "r"))==NULL){
        printf("Cannot open cert file, %s %s\n", 
			cert_file, strerror(errno));
        return -1;
    }
	if (compress) { /* file is gziped already */
		struct stat stat_buf;

		stat(cert_file, &stat_buf);
		derlen = stat_buf.st_size;
		der = malloc(derlen);
		if (der == NULL) {
			printf("file %s is too big, %lu\n",
				cert_file, (unsigned long)derlen);
			return-1 ;
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
		der = (u8 *) malloc(derlen);
		p = der;
		i2d_X509(cert, &p);
	}
    fclose(fp);
	sc_hex_to_bin(cert_id, buf,&buflen);
	
	switch (buf[0]) {
		case 0x9a: sc_format_path("0101",&path); break;
		case 0x9b: sc_format_path("0500",&path); break;
		case 0x9c: sc_format_path("0100",&path); break;
		case 0x9d: sc_format_path("0102",&path); break;
		default:
			fprintf(stderr,"cert must be 9A, 9B, 9C or 9D\n");
			return 2;
	}

	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "select file failed\n");
		 return -1;
	}
	/* we pass compress as the flag to card-piv.c write_binary */
	r = sc_write_binary(card, 0, der, derlen, compress); 
	
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
	
	r = sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &opts);
	if (r)
		fprintf(stderr, " admin_mode failed %d\n", r);
	return r;
}

#if 0
/* generate a req using xxx as subject */
static int req()
{
	fprintf(stderr, "Not Implemented yet\n");
	return -1;
}
#endif

/* generate a new key pair, and save public key in newkey */
static int gen_key(const char * key_info)
{
	int r;
	u8 buf[2];
	size_t buflen = 2;
	struct sc_cardctl_cryptoflex_genkey_info 
		keydata = { 0x9a, 1024, 0, NULL, 0};
	unsigned long expl;
	u8 expc[4];
	
	sc_hex_to_bin(key_info, buf, &buflen);
	if (buflen != 2) {
		fprintf(stderr, "<keyref>:<algid> invalid, example: 9A:06\n");
		return 2;
	}
	switch (buf[0]) {
		case 0x9a:
		case 0x9b:
		case 0x9c:
		case 0x9d:
			keydata.key_num = buf[0];
			break;
		default:
			fprintf(stderr, "<keyref>:<algid> must be 9A, 9B, 9C or 9D\n");
			return 2;
	}

	switch (buf[1]) {
		case 5: keydata.key_bits = 3072; break;
		case 6: keydata.key_bits = 1024; break;
		case 7: keydata.key_bits = 2048; break;
		default:
			fprintf(stderr, "<keyref>:<algid> algid, 05, 06, 07 for 3072, 1024, 2048\n");
			return 2;
	}

	r = sc_card_ctl(card, SC_CARDCTL_CRYPTOFLEX_GENERATE_KEY, &keydata);
	if (r) {
		fprintf(stderr, "gen_key failed %d\n", r);
		return r;
	}
	
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

	if (bp) 
		PEM_write_bio_RSAPublicKey(bp, newkey);

	return r;

}

static int send_apdu(void)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE], sbuf[SC_MAX_APDU_BUFFER_SIZE],
	   rbuf[SC_MAX_APDU_BUFFER_SIZE], *p;
	size_t len, len0, r;
	int c;

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);
		if (len0 < 4) {
			fprintf(stderr, "APDU too short (must be at least 4 bytes).\n");
			return 2;
		}
		len = len0;
		p = buf;
		memset(&apdu, 0, sizeof(apdu));
		apdu.cla = *p++;
		apdu.ins = *p++;
		apdu.p1 = *p++;
		apdu.p2 = *p++;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		len -= 4;
		if (len > 1) {
			apdu.lc = *p++;
			len--;
			memcpy(sbuf, p, apdu.lc);
			apdu.data = sbuf;
			apdu.datalen = apdu.lc;
			if (len < apdu.lc) {
				fprintf(stderr, "APDU too short (need %lu bytes).\n",
					(unsigned long) apdu.lc-len);
				return 2;
			}
			len -= apdu.lc;
			if (len) {
				apdu.le = *p++;
				if (apdu.le == 0)
					apdu.le = 256;
				len--;
				apdu.cse = SC_APDU_CASE_4_SHORT;
			} else
				apdu.cse = SC_APDU_CASE_3_SHORT;
			if (len) {
				fprintf(stderr, "APDU too long (%lu bytes extra).\n", (unsigned long)len);
				return 2;
			}
		} else if (len == 1) {
			apdu.le = *p++;
			if (apdu.le == 0)
				apdu.le = 256;
			len--;
			apdu.cse = SC_APDU_CASE_2_SHORT;
		} else
			apdu.cse = SC_APDU_CASE_1;
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
	int compress_cert = 0;
	int do_req = 0;
	int do_print_serial = 0;
	int do_print_name = 0;
	int action_count = 0;
	const char *opt_driver = NULL;
	const char *out_file = NULL;
	const char *in_file = NULL;
	const char *cert_id = NULL;
	const char *key_info = NULL;
	const char *admin_info = NULL;
		
	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "nA:G:Z:C:Ri:o:fvs:c:w", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help);
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
		case 'Z':
			compress_cert = 1;
		case 'C':
			do_load_cert = 1;
			cert_id = optarg;
			action_count++;
			break;
		case 'R':
			do_req = 1;
			action_count++;
			break;
		case 'i':
			in_file = optarg;
			break;
		case 'o':
			out_file = optarg;
			break;
		case 'r':
			opt_reader = atoi(optarg);
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
		util_print_usage_and_die(app_name, options, option_help);

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

	r = sc_establish_context(&ctx, app_name);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose > 1)
		ctx->debug = verbose-1;

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

	err = util_connect_card(ctx, &card, opt_reader, 0, opt_wait, verbose);
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
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
