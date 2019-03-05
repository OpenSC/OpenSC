/*
 * cardos-tool.c: Tool and Info about Card OS based tokens
 *
 * Copyright (C) 2008  Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright (C) 2007  Jean-Pierre Szikora <jean-pierre.szikora@uclouvain.be>
 * Copyright (C) 2003  Andreas Jellinghaus <aj@dungeon.inka.de>
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef ENABLE_OPENSSL
#include <openssl/des.h>
#include <openssl/sha.h>
#endif

#include "libopensc/opensc.h"
#include "util.h"

static const char *app_name = "cardos-tool";

static int opt_wait = 0;
static int verbose = 0;
static char *opt_reader = NULL;

static const struct option options[] = {
	{"help",	0, NULL, 'h'},
	{"info",	0, NULL, 'i'},
	{"format",	0, NULL, 'f'},
	{"startkey",	1, NULL, 's'},
	{"change-startkey",	1, NULL, 'S'},
	{"reader",	1, NULL, 'r'},
	{"card-driver", 1, NULL, 'c'},
	{"wait",	0, NULL, 'w'},
	{"verbose",	0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static const char *option_help[] = {
	"Print this help message",
	"Print information about this card",
	"Format this card erasing all content",
	"Specify startkey for format",
	"Change Startkey with given APDU command",
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

static int check_apdu(const sc_apdu_t *apdu)
{
	if (apdu->sw1 != 0x90 || apdu->sw2 != 0x00) {
		fprintf(stderr, "Some error occurred. Use '-v' several times to enable debug output.");
		return 1;
	}
	return 0;
}

static int cardos_info(void)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int is_cardos5 = 0;
	int r;

	if (verbose) {
		printf("Card ATR:\n");
		util_hex_dump_asc(stdout, card->atr.value, card->atr.len, -1);
	} else {
		char tmp[SC_MAX_ATR_SIZE*3];
		sc_bin_to_hex(card->atr.value, card->atr.len, tmp, sizeof(tmp) - 1, ':');
		fprintf(stdout,"%s\n",tmp);
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	printf("Info : %s\n", apdu.resp);

	apdu.p2 = 0x82;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resp[0] == 0xc9)
		is_cardos5 = 1;

	apdu.p2 = 0x81;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (is_cardos5)	{
		printf("Serial number: %02x %02x %02x %02x %02x %02x %02x %02x\n",
			apdu.resp[0], apdu.resp[1], apdu.resp[2], apdu.resp[3],
			apdu.resp[4], apdu.resp[5], apdu.resp[6], apdu.resp[7]);
	} else	{
		printf("Chip type: %d\n", apdu.resp[8]);
		printf("Serial number: %02x %02x %02x %02x %02x %02x\n",
			   apdu.resp[10], apdu.resp[11], apdu.resp[12],
			   apdu.resp[13], apdu.resp[14], apdu.resp[15]);
		printf("Full prom dump:\n");
		if (apdu.resplen)
			util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}

	apdu.p2 = 0x82;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	printf("OS Version: %d.%d", apdu.resp[0], apdu.resp[1]);
	if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x02) {
		printf(" (that's CardOS M4.0)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x03) {
		printf(" (that's CardOS M4.01)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x04) {
		printf(" (that's CardOS M4.01a)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x06) {
		printf(" (that's CardOS M4.2)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x07) {
		printf(" (that's CardOS M4.3)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x08) {
		printf(" (that's CardOS M4.3B)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x09) {
		printf(" (that's CardOS M4.2B)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x0B) {
		printf(" (that's CardOS M4.2C)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 0x0D) {
		printf(" (that's CardOS M4.4)\n");
	} else if (apdu.resp[0] == 0xc9 && apdu.resp[1] == 0x01) {
		printf(" (that's CardOS V5.0)\n");
	} else if (apdu.resp[0] == 0xc9 &&
			(apdu.resp[1] == 0x02 || apdu.resp[1] == 0x03)) {
		printf(" (that's CardOS V5.3)\n");
	} else {
		printf(" (unknown Version)\n");
	}

	apdu.p2 = 0x83;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Current life cycle: ");
	if (rbuf[0] == 0x34) {
		printf("%d (manufacturing)\n", rbuf[0]);
	} else if (rbuf[0] == 0x26) {
		if (is_cardos5)
			printf("%d (physinit)\n", rbuf[0]);
		else
			printf("%d (initialization)\n", rbuf[0]);
	} else if (rbuf[0] == 0x23) {
		printf("%d (physpers)\n", rbuf[0]);
	} else if (rbuf[0] == 0x24) {
		printf("%d (personalization)\n", rbuf[0]);
	} else if (rbuf[0] == 0x20) {
		printf("%d (administration)\n", rbuf[0]);
	} else if (rbuf[0] == 0x10) {
		printf("%d (operational)\n", rbuf[0]);
	} else if (rbuf[0] == 0x29) {
		printf("%d (erase in progress)\n", rbuf[0]);
	} else if (rbuf[0] == 0x3F) {
		printf("%d (death)\n", rbuf[0]);
	} else {
		printf("%d (unknown)\n", rbuf[0]);
	}

	apdu.p2 = 0x84;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Security Status of current DF:\n");
	util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	apdu.p2 = 0x85;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Free memory : %d\n", rbuf[0]<<8|rbuf[1]);

	apdu.p2 = 0x86;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	if (rbuf[0] == 0x00) {
		printf("ATR Status: 0x%d ROM-ATR\n",rbuf[0]);
	} else if (rbuf[0] == 0x80)	{
		printf("ATR Status: 0x%d EEPROM-ATR\n",rbuf[0]);
	} else {
		printf("ATR Status: 0x%d unknown\n",rbuf[0]);
	}

	apdu.p2 = 0x88;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Packages installed:\n");
	util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	apdu.p2 = 0x89;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	if (is_cardos5)
		printf("Ram size: %d, Eeprom size: %d, cpu type: %x, chip config: %d, chip manufacturer: %d\n",
			rbuf[0]<<8|rbuf[1], rbuf[2]<<8|rbuf[3], rbuf[4], rbuf[6], rbuf[7]);
	else
		printf("Ram size: %d, Eeprom size: %d, cpu type: %x, chip config: %d\n",
			rbuf[0]<<8|rbuf[1], rbuf[2]<<8|rbuf[3], rbuf[4], rbuf[5]);

	apdu.p2 = 0x8a;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	if (is_cardos5)
		printf("Free eeprom memory: %d\n", rbuf[0]<<24|rbuf[1]<<16|rbuf[2]<<8|rbuf[3]);
	else
		printf("Free eeprom memory: %d\n", rbuf[0]<<8|rbuf[1]);

	apdu.p2 = 0x8d;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Current Maximum Data Field Length: %d\n", rbuf[0]<<8|rbuf[1]);

	if (is_cardos5)	{
		apdu.p2 = 0x8B;
		apdu.resplen = sizeof(rbuf);
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n",
				sc_strerror(r));
			return 1;
		}
		if (check_apdu(&apdu))
			return 1;

		printf("Complete chip production data:\n");
		util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
	}

	apdu.p2 = 0x96;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("System keys: PackageLoadKey (version 0x%02x, retries %d)\n",
			rbuf[0], rbuf[1]);
	printf("System keys: StartKey (version 0x%02x, retries %d)\n",
			rbuf[2], rbuf[3]);

	apdu.p2 = 0x87;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("Path to current DF:\n");
	util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	return 0;
}

#ifdef ENABLE_OPENSSL
static int cardos_sm4h(const unsigned char *in, size_t inlen, unsigned char
	*out, size_t outlen, const unsigned char *key, size_t keylen) {
	/* using a buffer with an APDU, build an SM 4h APDU for cardos */

	int plain_lc;	/* data size in orig APDU */
	unsigned int mac_input_len, enc_input_len;
	unsigned char *mac_input, *enc_input;
	DES_key_schedule ks_a, ks_b;
	DES_cblock des_in,des_out;
	unsigned int i,j;

	if (keylen != 16) {
		printf("key has wrong size, need 16 bytes, got %"SC_FORMAT_LEN_SIZE_T"d. aborting.\n",
		       keylen);
		return 0;
	}

	if (inlen < 4)
		return 0;	/* failed, apdu too short */
	if (inlen <= 5)
		plain_lc = 0;
	if (inlen > 5)
		plain_lc = in[4];

	/* 4 + plain_lc plus 0..7 bytes of padding */
	mac_input_len = 4 + plain_lc;
	while (mac_input_len % 8) mac_input_len++;

	mac_input = calloc(1,mac_input_len);
	if (!mac_input) {
		printf("out of memory, aborting\n");
		return 0;
	}
	mac_input[0] = in[1]; 	/* ins */
	mac_input[1] = in[2]; 	/* p1 */
	mac_input[2] = in[3]; 	/* p2 */
	mac_input[3] = plain_lc + 8;
	if (plain_lc)	/* copy data from in APDU */
		memcpy(&mac_input[4],&in[5],plain_lc);
	/* calloc already did the ansi padding: rest is 00 */

	/* prepare des key using first 8 bytes of key */
	DES_set_key((const_DES_cblock*) &key[0], &ks_a);
	/* prepare des key using second 8 bytes of key */
	DES_set_key((const_DES_cblock*) &key[8], &ks_b);

	/* first block: XOR with IV and encrypt with key A IV is 8 bytes 00 */
	for (i=0; i < 8; i++) des_in[i] = mac_input[i]^00;
	DES_ecb_encrypt(&des_in, &des_out, &ks_a, 1);

	/* all other blocks: XOR with prev. result and encrypt with key A */
	for (j=1; j < (mac_input_len / 8); j++) {
		for (i=0; i < 8; i++) des_in[i] = mac_input[i+j*8]^des_out[i];
		DES_ecb_encrypt(&des_in, &des_out, &ks_a, 1);
	}

	/* now decrypt with key B and encrypt with key A again */
	/* (a noop if key A and B are the same, e.g. 8 bytes ff */
	for (i=0; i < 8; i++) des_in[i] = des_out[i];
	DES_ecb_encrypt(&des_in, &des_out, &ks_b, 0);
	for (i=0; i < 8; i++) des_in[i] = des_out[i];
	DES_ecb_encrypt(&des_in, &des_out, &ks_a, 1);

	/* now we want to enc:
 	 * orig APDU data plus mac (8 bytes) plus iso padding (1-8 bytes) */
	enc_input_len = plain_lc + 8 + 1;
	while (enc_input_len % 8) enc_input_len++;

	enc_input = calloc(1,enc_input_len);
	if (!enc_input) {
		free(mac_input);
		printf("out of memory, aborting\n");
		return 0;
	}
	if (plain_lc)
		memcpy(&enc_input[0],&in[5],plain_lc);
	for (i=0; i < 8; i++) enc_input[i+plain_lc] = des_out[i];
	enc_input[plain_lc+8] = 0x80; /* iso padding */
	/* calloc already cleared the remaining bytes to 00 */

	if (outlen < 5 + enc_input_len) {
		free(mac_input);
		free(enc_input);
		printf("output buffer too small, aborting.\n");
		return 0;
	}

	out[0] = in[0];	/* cla */
	out[1] = in[1];	/* ins */
	out[2] = in[2];	/* p1 */
	out[3] = in[3];	/* p2 */
	out[4] = enc_input_len;	/* lc */

	/* encrypt first block */

	/* xor data and IV (8 bytes 00) to get input data */
	for (i=0; i < 8; i++) des_in[i] = enc_input[i] ^ 00;

	/* encrypt with des2 (triple des, but using keys A-B-A) */
	DES_ecb2_encrypt(&des_in, &des_out, &ks_a, &ks_b, 1);

	/* copy encrypted bytes into output */
	for (i=0; i < 8; i++) out[5+i] = des_out[i];

	/* encrypt other blocks (usually one) */
	for (j=1; j < (enc_input_len / 8); j++) {
		/* xor data and prev. result to get input data */
		for (i=0; i < 8; i++) des_in[i] = enc_input[i+j*8] ^ des_out[i];

		/* encrypt with des2 (triple des, but using keys A-B-A) */
		DES_ecb2_encrypt(&des_in, &des_out, &ks_a, &ks_b, 1);

		/* copy encrypted bytes into output */
		for (i=0; i < 8; i++) out[5+8*j+i] = des_out[i];
	}
	if (verbose)	{
		printf ("Unencrypted APDU:\n");
		util_hex_dump_asc(stdout, in, inlen, -1);
		printf ("Encrypted APDU:\n");
		util_hex_dump_asc(stdout, out, out[4] + 5, -1);
		printf ("\n");
	}
	free(mac_input);
	free(enc_input);
	return 1;
}
#endif

#ifdef ENABLE_OPENSSL
static int cardos_format(const char *opt_startkey)
{
	unsigned const char startkey[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	sc_apdu_t apdu;
	u8 rbuf[256];
	int r;

	if (opt_startkey) {
		fprintf(stderr, "startkey option not implemented yet, aborting!\n");
		return 1;
		/* TODO: instead validate/parse opt_startkey into startkey */
		/* format would be ii:vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
		/* with "ii" the startkey index as hex number and */
		/* "vv" the 16 byte value in hex (32 chars) */
	}

	if (verbose)	{
		printf ("StartKey:\n");
		util_hex_dump_asc(stdout, startkey, 16, -1);
		}

	/* use GET DATA for version - 00 ca 01 82
	 * returns e.g. c8 09 for 4.2B
	 */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x82;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen != 0x02) {
		printf("did not receive version info, aborting\n");
		return 1;
	}
	if ((rbuf[0] != 0xc8 || rbuf[1] != 0x09) &&	/* M4.2B */
		(rbuf[0] != 0xc8 || rbuf[1] != 0x08) && /* M4.3B */
		(rbuf[0] != 0xc8 || rbuf[1] != 0x0B) && /* M4.2C */
		(rbuf[0] != 0xc8 || rbuf[1] != 0x0D)) { /* M4.4 */
		printf("currently only CardOS M4.2B, M4.2C, M4.3B and M4.4 are supported, aborting\n");
		return 1;
	}

	/* GET DATA for startkey index - 00 ca 01 96
	 * returns 6 bytes PackageLoadKey.Version, PackageLoadKey.Retry
	 * Startkey.Version, Startkey.Retry, 2 internal data byes */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x96;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen < 0x04) {
		printf("expected 4-6 bytes form GET DATA for startkey data, but got only %"SC_FORMAT_LEN_SIZE_T"u\n",
		       apdu.resplen);
		printf("aborting\n");
		return 1;
	}

	if (apdu.resp[2] != 0xff) {
		printf("startkey version is 0x%02x, currently we support only 0xff\n", (int) apdu.resp[2]);
		printf("aborting\n");
		return 1;
	}

	if (apdu.resp[3] < 5) {
		printf("startkey has only %d tries left. to be safe: aborting\n", apdu.resp[3]);
		return 1;
	}

	/* first run GET DATA for lifecycle	 00 CA 01 83
	 * returns 34 MANUFACTURING 20 ADMINISTRATION 10 OPERATIONAL
	 * 26 INITIALIZATION, 23 PERSONALIZATION 3f DEATH
	 * 29 ERASE IN PROGRESS
 	 * */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x83;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	if (apdu.resp[0] == 0x34) {
		printf("card in manufacturing state\n");
		goto erase_state;

		/* we can leave manufacturing mode with FORMAT,
 		 * but before we do that, we need to change the secret
 		 * siemens start key to the default 0xff start key.
 		 * we know the APDU for that, but it is secret and
 		 * siemens so far didn't allow us to publish it.
 		 */
	}

	if (apdu.resp[0] != 0x10 && apdu.resp[0] != 0x20) {
		printf("card is in unknown state 0x%02x, aborting\n",
			(int) apdu.resp[0]);
		return 1;

		/* we should handle ERASE IN PROGRESS (29) too */
	}

	if (apdu.resp[0] == 0x20) {
		printf("card in administrative state, ok\n");
		goto admin_state;
	}
	printf("card in operational state, need to switch to admin state\n");

	/* PHASE CONTROL 80 10 00 00 */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x80;
	apdu.ins = 0x10;
	apdu.p1 = 0x00;
	apdu.p2 = 0x00;
	apdu.resp = 00;
	apdu.lc = 0;
	apdu.le = 00;
	apdu.cse = SC_APDU_CASE_1;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	/* use GET DATA for lifecycle once more */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x83;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resp[0] != 0x20) {
		printf("card not in administrative state, failed\n");
		printf("aborting\n");
		return 1;
	}

admin_state:
	/* use GET DATA for packages - 00 ca 01 88
	 * returns e1 LEN MM 04 ID ID ID ID 8f 01 SS
	 * MM = Manufacturing ID (01 .. 3f = Siemens
	 * ID ID ID ID = Id of the package
	 * SS = License state (01 enabled, 00 disabled
	 */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x88;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen != 0x00) {
		printf("card has packages installed.\n");
		printf("you would loose those, and we can't re-install them.\n");
		printf("to protect you card: aborting\n");
		return 1;
	}



	/* now we need to erase the card. Our command is:
	 * 	ERASE FILES 84 06 00 00
	 * but it needs to be send using SM 4h mode (signed and enc.)
	 */
	{
		unsigned const char erase_apdu[] = { 0x84, 0x06, 0x00, 0x00 };
		if (! cardos_sm4h(erase_apdu, sizeof(erase_apdu),
			rbuf, sizeof(rbuf), startkey, sizeof(startkey)))
			return 1;
		if (verbose)	{
			printf ("Erasing EEPROM!\n");
			}
		memset(&apdu, 0, sizeof(apdu));
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.cla = rbuf[0];
		apdu.ins = rbuf[1];
		apdu.p1 = rbuf[2];
		apdu.p2 = rbuf[3];
		apdu.lc = rbuf[4];
		apdu.data = &rbuf[5];
		apdu.datalen = rbuf[4];

		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n",
				sc_strerror(r));
			return 1;
		}
		if (check_apdu(&apdu))
			return 1;
	}

erase_state:

	/* next we need to format the card. Our command is:
	 * 	FORMAT 84 40 00 01
	 * 	with P2 = 01 (go to admin mode after format)
	 * and with data: T L V with tag 62 and value: more TLV
	 * 		81 02 00 80	Main Folder size 0x0080
	 * 		85 01 01 	no death bit, no deactivation bit,
	 * 					but checksums bit
	 * 		86 0a 00 ... 	10 bytes AC with all set to allow (00)
	 * 	not included: CB tag with secure mode definition
	 * 			(defaults are fine for us)
	 *
	 * this APDU needs to be send using SM 4h mode (signed and enc.)
	 */
	{
		unsigned const char format_apdu[] = {
			0x84, 0x40, 0x00, 0x01, 0x15,
				0x62, 0x13,
					0x81, 0x02, 0x00, 0x80,
					0x85, 0x01, 0x01,
	0x86, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		if (verbose)	{
			printf ("Formatting!\n");
			}
		if (! cardos_sm4h(format_apdu, sizeof(format_apdu),
			rbuf, sizeof(rbuf), startkey, sizeof(startkey)))
			return 1;

		memset(&apdu, 0, sizeof(apdu));
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.cla = rbuf[0];
		apdu.ins = rbuf[1];
		apdu.p1 = rbuf[2];
		apdu.p2 = rbuf[3];
		apdu.lc = rbuf[4];
		apdu.data = &rbuf[5];
		apdu.datalen = rbuf[4];

		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "APDU transmit failed: %s\n",
				sc_strerror(r));
			return 1;
		}
		if (check_apdu(&apdu))
			return 1;
	}
	return 0;
}
# else /* ENABLE_OPENSSL */
static int cardos_format(const char *opt_startkey)
{
	printf("Formatting CardOS cards requires OpenSC built with OpenSSL.\n");
	printf("Aborting\n");
	return 1;
}
#endif /* ENABLE_OPENSSL */

#ifdef ENABLE_OPENSSL
static int cardos_change_startkey(const char *change_startkey_apdu)
{
	#define MAX_APDU 60
	unsigned char cardos_version[2];
	unsigned char apdu_bin[MAX_APDU];
	size_t apdu_len=MAX_APDU;
	unsigned char checksum[SHA_DIGEST_LENGTH];

	static const unsigned char cardos_43b_checksum[SHA_DIGEST_LENGTH] =
		{  0x5C, 0xD6, 0x8C, 0x2C, 0x24, 0x77, 0x3C, 0xDC,
		   0x93, 0x73, 0xD8, 0x4B, 0x47, 0x29, 0x19, 0x70,
		   0x9F, 0xA2, 0x42, 0xB4  };
	sc_apdu_t apdu;
	u8 rbuf[256];
	int r;

	if (!change_startkey_apdu) {
		printf("Missing change StartKey, aborting\n");
		return 1;
	}

	if (verbose)	{
		printf ("Change StartKey APDU:\n");
		util_hex_dump_asc(stdout, (unsigned char *)change_startkey_apdu,
			strlen(change_startkey_apdu), -1);
		}

	/* use GET DATA for version - 00 ca 01 82
	 * returns e.g. c8 09 for 4.2B
	 */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x82;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen != 0x02) {
		printf("did not receive version info, aborting\n");
		return 1;
	}

	/* check all supported versions here. need a checksum check
	   for each of them below */
	if ( (rbuf[0] != 0xc8 || rbuf[1] != 0x08) ) { /* M4.3B */
		printf("currently only CardOS M4.01, M4.2B, M4.2C and M4.3B are supported, aborting\n");
		return 1;
	}
	cardos_version[0] = rbuf[0];
	cardos_version[1] = rbuf[1];

	/* GET DATA for startkey index - 00 ca 01 96
	 * returns 6 bytes PackageLoadKey.Version, PackageLoadKey.Retry
	 * Startkey.Version, Startkey.Retry, 2 internal data byes */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x96;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen < 0x04) {
		printf("expected 4-6 bytes form GET DATA for startkey data, but got only %"SC_FORMAT_LEN_SIZE_T"u\n",
		       apdu.resplen);
		printf("aborting\n");
		return 1;
	}

	if (apdu.resp[2] != 0x00) {
		printf("startkey version is 0x%02x, currently we support only 0x00\n", (int) apdu.resp[3]);
		printf("aborting\n");
		return 1;
	}

	if (apdu.resp[3] < 5) {
		printf("startkey has only %d tries left. to be safe: aborting\n", apdu.resp[3]);
		return 1;
	}

	/* now check if the correct APDU was passed */
	if (sc_hex_to_bin(change_startkey_apdu, apdu_bin, &apdu_len) != 0) {
		printf("can't convert startkey apdu to binary format: aborting\n");
		return 1;
	}
	SHA1(apdu_bin, apdu_len, checksum);

	if (cardos_version[0] == 0xc8 && cardos_version[1] == 0x08) {
		if (memcmp(checksum, cardos_43b_checksum, SHA_DIGEST_LENGTH) != 0) {
			printf("change startkey apdu is wrong, checksum doesn't match\n");
			util_hex_dump_asc(stdout, checksum, SHA_DIGEST_LENGTH, -1);
			util_hex_dump_asc(stdout, cardos_43b_checksum, SHA_DIGEST_LENGTH, -1);
			printf("aborting\n");
			return 1;
		}
		goto change_startkey;
	}

	printf("checksum for your card not yet implemented, aborting\n");
	return 1;

change_startkey:
	/* run change startkey apdu */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = apdu_bin[0];
	apdu.ins = apdu_bin[1];
	apdu.p1 = apdu_bin[2];
	apdu.p2 = apdu_bin[3];
	apdu.lc = apdu_bin[4];
	apdu.data = &apdu_bin[5];
	apdu.datalen = apdu.lc;
	apdu.resp = 00;
	apdu.le = 00;
	apdu.cse = SC_APDU_CASE_3_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;

	printf("change startkey command issued with success\n");

	/* GET DATA for startkey index - 00 ca 01 96
	 * returns 6 bytes PackageLoadKey.Version, PackageLoadKey.Retry
	 * Startkey.Version, Startkey.Retry, 2 internal data byes */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x96;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (check_apdu(&apdu))
		return 1;
	if (apdu.resplen < 0x04) {
		printf("expected 4-6 bytes form GET DATA for startkey data, but got only %"SC_FORMAT_LEN_SIZE_T"u\n",
		       apdu.resplen);
		printf("aborting\n");
		return 1;
	}

	if (apdu.resp[2] != 0xff) {
		printf("startkey version is 0x%02x, should have been changed to 0xff.\n", apdu.resp[2]);
		printf("aborting\n");
		return 1;
	}

	printf("startkey is now 0xff, success!\n");
	return 0;
}
# else /* ENABLE_OPENSSL */
static int cardos_change_startkey(const char *change_startkey_apdu)   {
	fprintf(stderr, "Changing the startkey requires OpenSC built with OpenSSL.\n");
	fprintf(stderr, "Aborting\n");
	return 1;
}
#endif

int main(int argc, char *argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_info = 0;
	int do_format = 0;
	int do_change_startkey = 0;
	int action_count = 0;
	const char *opt_driver = NULL;
	const char *opt_startkey = NULL;
	const char *opt_change_startkey = NULL;
	sc_context_param_t ctx_param;

	while (1) {
		c = getopt_long(argc, argv, "hifs:r:vdc:wS:", options,
				&long_optind);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			printf("NB! This tool is only for Siemens CardOS based cards!\n\n");
			util_print_usage_and_die(app_name, options, option_help, NULL);
		case 'i':
			do_info = 1;
			action_count++;
			break;
		case 'f':
			do_format = 1;
			action_count++;
			break;
		case 's':
			opt_startkey = optarg;
			break;
		case 'S':
			do_change_startkey = 1;
			opt_change_startkey = optarg;
			action_count++;
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

	/* create sc_context_t object */
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n",
			sc_strerror(r));
		return 1;
	}

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n",
				opt_driver);
			err = 1;
			goto end;
		}
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (err)
		goto end;

	if (do_info) {
		if ((err = cardos_info())) {
			goto end;
		}
		action_count--;
	}
	if (do_change_startkey) {
		if ((err = cardos_change_startkey(opt_change_startkey))) {
			goto end;
		}
		action_count--;
	}
	if (do_format) {
		if ((err = cardos_format(opt_startkey))) {
			goto end;
		}
		action_count--;
	}
      end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	sc_release_context(ctx);
	return err;
}
