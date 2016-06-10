/*
 * card-mcrd.c: Support for MICARDO cards
 *
 * Copyright (C) 2004  Martin Paljak <martin@martinpaljak.net>
 * Copyright (C) 2004  Priit Randla <priit.randla@eyp.ee>
 * Copyright (C) 2003  Marie Fischer <marie@vtl.ee>
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2002  g10 Code GmbH
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "esteid.h"

static struct sc_atr_table mcrd_atrs[] = {
	{"3B:FF:94:00:FF:80:B1:FE:45:1F:03:00:68:D2:76:00:00:28:FF:05:1E:31:80:00:90:00:23", NULL,
	  "Micardo 2.1/German BMI/D-Trust", SC_CARD_TYPE_MCRD_GENERIC, 0, NULL},
	{"3b:6f:00:ff:00:68:d2:76:00:00:28:ff:05:1e:31:80:00:90:00", NULL,
	  "D-Trust", SC_CARD_TYPE_MCRD_DTRUST, 0, NULL},
	{"3b:ff:11:00:ff:80:b1:fe:45:1f:03:00:68:d2:76:00:00:28:ff:05:1e:31:80:00:90:00:a6", NULL,
	  "D-Trust", SC_CARD_TYPE_MCRD_DTRUST, 0, NULL},
	/* Certain pcsc-lite versions (1.5.3 for example on Ubuntu 10.04) incorrectly trunkate the wram ATR to the length of the cold ATR  */
	/* See opensc.conf for further information */
	{"3B:FE:94:00:FF:80:B1:FA:45:1F:03:45:73:74:45:49:44:20", NULL, "Broken EstEID 1.1 warm", SC_CARD_TYPE_MCRD_ESTEID_V11, 0, NULL},
	{"3b:fe:94:00:ff:80:b1:fa:45:1f:03:45:73:74:45:49:44:20:76:65:72:20:31:2e:30:43", NULL, "EstEID 1.0 cold", SC_CARD_TYPE_MCRD_ESTEID_V10, 0, NULL},
	{"3b:6e:00:ff:45:73:74:45:49:44:20:76:65:72:20:31:2e:30", NULL, "EstEID 1.0 cold", SC_CARD_TYPE_MCRD_ESTEID_V10, 0, NULL},
	{"3b:de:18:ff:c0:80:b1:fe:45:1f:03:45:73:74:45:49:44:20:76:65:72:20:31:2e:30:2b", NULL, "EstEID 1.0 cold 2006", SC_CARD_TYPE_MCRD_ESTEID_V10, 0, NULL},
	{"3b:5e:11:ff:45:73:74:45:49:44:20:76:65:72:20:31:2e:30", NULL, "EstEID 1.0 warm 2006", SC_CARD_TYPE_MCRD_ESTEID_V10, 0, NULL},
	{"3b:6e:00:00:45:73:74:45:49:44:20:76:65:72:20:31:2e:30", NULL, "EstEID 1.1 cold", SC_CARD_TYPE_MCRD_ESTEID_V11, 0, NULL},
	{"3B:FE:18:00:00:80:31:FE:45:45:73:74:45:49:44:20:76:65:72:20:31:2E:30:A8", NULL, "EstEID 3.0 (dev1) cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3B:FE:18:00:00:80:31:FE:45:80:31:80:66:40:90:A4:56:1B:16:83:01:90:00:86", NULL, "EstEID 3.0 (dev1) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fe:18:00:00:80:31:fe:45:80:31:80:66:40:90:a4:16:2a:00:83:01:90:00:e1", NULL, "EstEID 3.0 (dev2) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fe:18:00:00:80:31:fe:45:80:31:80:66:40:90:a4:16:2a:00:83:0f:90:00:ef", NULL, "EstEID 3.0 (18.01.2011) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fa:18:00:00:80:31:fe:45:fe:65:49:44:20:2f:20:50:4b:49:03", NULL, "EstEID 3.5 cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL },
	{"3b:f8:18:00:00:80:31:fe:45:fe:41:5a:45:20:44:49:54:33", NULL, "AzeDIT 3.5 cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL },
	{NULL, NULL, NULL, 0, 0, NULL}
};

static unsigned char EstEID_v3_AID[] = {0xF0, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30};
static unsigned char EstEID_v35_AID[] = {0xD2, 0x33, 0x00, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x33, 0x35};
static unsigned char AzeDIT_v35_AID[] = {0xD0, 0x31, 0x00, 0x00, 0x00, 0x44, 0x69, 0x67, 0x69, 0x49, 0x44};

static struct sc_card_operations mcrd_ops;
static struct sc_card_driver mcrd_drv = {
	"MICARDO 2.1 / EstEID 1.0 - 3.0",
	"mcrd",
	&mcrd_ops,
	NULL, 0, NULL
};

static const struct sc_card_operations *iso_ops = NULL;

enum {
	MCRD_SEL_MF = 0x00,
	MCRD_SEL_DF = 0x01,
	MCRD_SEL_EF = 0x02,
	MCRD_SEL_PARENT = 0x03,
	MCRD_SEL_AID = 0x04
};

#define MFID 0x3F00
#define EF_KeyD 0x0013		/* File with extra key information. */
#define EF_Rule 0x0030		/* Default ACL file. */

#define MAX_CURPATH 10

struct rule_record_s {
	struct rule_record_s *next;
	int recno;
	size_t datalen;
	u8 data[1];
};

struct keyd_record_s {
	struct keyd_record_s *next;
	int recno;
	size_t datalen;
	u8 data[1];
};

struct df_info_s {
	struct df_info_s *next;
	unsigned short path[MAX_CURPATH];
	size_t pathlen;
	struct rule_record_s *rule_file;	/* keeps records of EF_Rule. */
	struct keyd_record_s *keyd_file;	/* keeps records of EF_KeyD. */
};

struct mcrd_priv_data {
	unsigned short curpath[MAX_CURPATH];	/* The currently selected path. */
	size_t curpathlen;	/* Length of this path or 0 if unknown. */
	int is_ef;		/* True if the path points to an EF. */
	struct df_info_s *df_infos;
	sc_security_env_t sec_env;	/* current security environment */
};

#define DRVDATA(card)        ((struct mcrd_priv_data *) ((card)->drv_data))

static int load_special_files(sc_card_t * card);
static int select_part(sc_card_t * card, u8 kind, unsigned short int fid,
		       sc_file_t ** file);

/* Return the DF_info for the current path.  If does not yet exist,
   create it.  Returns NULL on error. */
static struct df_info_s *get_df_info(sc_card_t * card)
{
	sc_context_t *ctx = card->ctx;
	struct mcrd_priv_data *priv = DRVDATA(card);
	struct df_info_s *dfi;

	assert(!priv->is_ef);

	if (!priv->curpathlen) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "no current path to find the df_info\n");
		return NULL;
	}

	for (dfi = priv->df_infos; dfi; dfi = dfi->next) {
		if (dfi->pathlen == priv->curpathlen
		    && !memcmp(dfi->path, priv->curpath,
			       dfi->pathlen * sizeof *dfi->path))
			return dfi;
	}
	/* Not found, create it. */
	dfi = calloc(1, sizeof *dfi);
	if (!dfi) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "out of memory while allocating df_info\n");
		return NULL;
	}
	dfi->pathlen = priv->curpathlen;
	memcpy(dfi->path, priv->curpath, dfi->pathlen * sizeof *dfi->path);
	dfi->next = priv->df_infos;
	priv->df_infos = dfi;
	return dfi;
}

static void clear_special_files(struct df_info_s *dfi)
{
	if (dfi) {
		while (dfi->rule_file) {
			struct rule_record_s *tmp = dfi->rule_file->next;
			free(dfi->rule_file);
			dfi->rule_file = tmp;
		}
		while (dfi->keyd_file) {
			struct keyd_record_s *tmp = dfi->keyd_file->next;
			free(dfi->keyd_file);
			dfi->keyd_file = tmp;
		}
	}
}

/* Some functionality straight from the EstEID manual.
 * Official notice: Refer to the Micardo 2.1 Public manual.
 * Sad side: not available without a NDA.
 */

static int mcrd_delete_ref_to_authkey(sc_card_t * card)
{
	sc_apdu_t apdu;
	int r;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xA4);

	sbuf[0] = 0x83;
	sbuf[1] = 0x00;
	apdu.data = sbuf;
	apdu.lc = 2;
	apdu.datalen = 2;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int mcrd_delete_ref_to_signkey(sc_card_t * card)
{
	sc_apdu_t apdu;
	int r;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	assert(card != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);

	sbuf[0] = 0x83;
	sbuf[1] = 0x00;
	apdu.data = sbuf;
	apdu.lc = 2;
	apdu.datalen = 2;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));

}

static int mcrd_set_decipher_key_ref(sc_card_t * card, int key_reference)
{
	sc_apdu_t apdu;
	sc_path_t path;
	int r;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 keyref_data[SC_ESTEID_KEYREF_FILE_RECLEN];
	assert(card != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
	/* track the active keypair  */
	sc_format_path("0033", &path);
	r = sc_select_file(card, &path, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Can't select keyref info file 0x0033");
	r = sc_read_record(card, 1, keyref_data,
			   SC_ESTEID_KEYREF_FILE_RECLEN, SC_RECORD_BY_REC_NR);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Can't read keyref info file!");

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "authkey reference 0x%02x%02x\n",
		 keyref_data[9], keyref_data[10]);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "signkey reference 0x%02x%02x\n",
		 keyref_data[19], keyref_data[20]);

	sbuf[0] = 0x83;
	sbuf[1] = 0x03;
	sbuf[2] = 0x80;
	switch (key_reference) {
	case 1:
		sbuf[3] = keyref_data[9];
		sbuf[4] = keyref_data[10];
		break;
	case 2:
		sbuf[3] = keyref_data[19];
		sbuf[4] = keyref_data[20];
		break;
	}
	apdu.data = sbuf;
	apdu.lc = 5;
	apdu.datalen = 5;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

int is_esteid_card(sc_card_t *card) {
	switch(card->type) {
		case SC_CARD_TYPE_MCRD_ESTEID_V10:
		case SC_CARD_TYPE_MCRD_ESTEID_V11:
		case SC_CARD_TYPE_MCRD_ESTEID_V30:
			return 1;
	}

	return 0;
}
static int mcrd_match_card(sc_card_t * card)
{
	int i = 0, r = 0;
	sc_apdu_t apdu;

	i = _sc_match_atr(card, mcrd_atrs, &card->type);
	if (i >= 0) {
		card->name = mcrd_atrs[i].name;
		return 1;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xA4, 0x04, 0x00);
	apdu.lc = sizeof(EstEID_v35_AID);
	apdu.data = EstEID_v35_AID;
	apdu.datalen = sizeof(EstEID_v35_AID);
	apdu.resplen = 0;
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "SELECT AID: %02X%02X", apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
	        sc_log(card->ctx, "AID found");
	        card->type = SC_CARD_TYPE_MCRD_ESTEID_V30;
	        return 1;
	}
	return 0;
}

static int mcrd_init(sc_card_t * card)
{
	unsigned long flags;
	struct mcrd_priv_data *priv;
	int r;
	sc_path_t tmppath;
	sc_apdu_t apdu;

	priv = calloc(1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;
	card->cla = 0x00;
	card->caps = SC_CARD_CAP_RNG;


	if (is_esteid_card(card)) {
		/* Reset the MULTOS card to get to a known state */
		if (card->type == SC_CARD_TYPE_MCRD_ESTEID_V11)
			sc_reset(card, 0);

		/* Select the EstEID AID to get to a known state.
		 * For some reason a reset is required as well... */
		if (card->type == SC_CARD_TYPE_MCRD_ESTEID_V30) {
			flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256;
			/* EstEID v3.0 has 2048 bit keys */
			_sc_card_add_rsa_alg(card, 2048, flags, 0);
			sc_reset(card, 0);

			sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xA4, 0x04, 0x00);
			apdu.lc = sizeof(EstEID_v3_AID);
			apdu.data = EstEID_v3_AID;
			apdu.datalen = sizeof(EstEID_v3_AID);
			apdu.resplen = 0;
			apdu.le = 0;
			r = sc_transmit_apdu(card, &apdu);
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "SELECT AID: %02X%02X", apdu.sw1, apdu.sw2);
			if(apdu.sw1 != 0x90 && apdu.sw2 != 0x00)
			{
				sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xA4, 0x04, 0x00);
	                        apdu.lc = sizeof(EstEID_v35_AID);
        	                apdu.data = EstEID_v35_AID;
                	        apdu.datalen = sizeof(EstEID_v35_AID);
                        	apdu.resplen = 0;
	                        apdu.le = 0;
				r = sc_transmit_apdu(card, &apdu);
	                        SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
        	                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "SELECT AID: %02X%02X", apdu.sw1, apdu.sw2);
				if (apdu.sw1 != 0x90 && apdu.sw2 != 0x00) {
					sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xA4, 0x04, 0x00);
					apdu.lc = sizeof(AzeDIT_v35_AID);
					apdu.data = AzeDIT_v35_AID;
					apdu.datalen = sizeof(AzeDIT_v35_AID);
					apdu.resplen = 0;
					apdu.le = 0;
					r = sc_transmit_apdu(card, &apdu);
					SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "SELECT AID: %02X%02X", apdu.sw1, apdu.sw2);
					if (apdu.sw1 != 0x90 && apdu.sw2 != 0x00)
						SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  SC_ERROR_CARD_CMD_FAILED);
				}
			}
		} else {
			/* EstEID v1.0 and 1.1 have 1024 bit keys */
			flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1;
			_sc_card_add_rsa_alg(card, 1024, flags, 0);
		}
	} else {
		flags = SC_ALGORITHM_RSA_RAW |SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
		_sc_card_add_rsa_alg(card, 512, flags, 0);
		_sc_card_add_rsa_alg(card, 768, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
	}

	priv->curpath[0] = MFID;
	priv->curpathlen = 1;

	sc_format_path ("3f00", &tmppath);
	r = sc_select_file (card, &tmppath, NULL);

	/* Not needed for the fixed EstEID profile */
	if (!is_esteid_card(card))
		load_special_files(card);

	return r;
}

static int mcrd_finish(sc_card_t * card)
{
	struct mcrd_priv_data *priv;

	if (card == NULL)
		return 0;
	priv = DRVDATA(card);
	while (priv->df_infos) {
		struct df_info_s *tmp = priv->df_infos->next;
		clear_special_files(priv->df_infos);
		priv->df_infos = tmp;
	}
	free(priv);
	return 0;
}

/* Load the rule and keyd file into our private data.
   Return 0 on success */
static int load_special_files(sc_card_t * card)
{
	sc_context_t *ctx = card->ctx;
	int r, recno;
	struct df_info_s *dfi;
	struct rule_record_s *rule;
	struct keyd_record_s *keyd;

	/* First check whether we already cached it. */
	dfi = get_df_info(card);
	if (dfi && dfi->rule_file)
		return 0;	/* yes. */
	clear_special_files(dfi);
	if (!dfi)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	/* Read rule file. Note that we bypass our cache here. */
	r = select_part(card, MCRD_SEL_EF, EF_Rule, NULL);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "selecting EF_Rule failed");

	for (recno = 1;; recno++) {
		u8 recbuf[256];
		r = sc_read_record(card, recno, recbuf, sizeof(recbuf),
				   SC_RECORD_BY_REC_NR);

		if (r == SC_ERROR_RECORD_NOT_FOUND)
			break;
		else if (r < 0) {
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		} else {
			rule = malloc(sizeof *rule + r);
			if (!rule)
				SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
			rule->recno = recno;
			rule->datalen = r;
			memcpy(rule->data, recbuf, r);
			rule->next = dfi->rule_file;
			dfi->rule_file = rule;
		}
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "new EF_Rule file loaded (%d records)\n", recno - 1);

	/* Read the KeyD file. Note that we bypass our cache here. */
	r = select_part(card, MCRD_SEL_EF, EF_KeyD, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "no EF_KeyD file available\n");
		return 0;	/* That is okay. */
	}
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "selecting EF_KeyD failed");

	for (recno = 1;; recno++) {
		u8 recbuf[256];
		r = sc_read_record(card, recno, recbuf, sizeof(recbuf),
				   SC_RECORD_BY_REC_NR);

		if (r == SC_ERROR_RECORD_NOT_FOUND)
			break;
		else if (r < 0) {
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		} else {
			keyd = malloc(sizeof *keyd + r);
			if (!keyd)
				SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
			keyd->recno = recno;
			keyd->datalen = r;
			memcpy(keyd->data, recbuf, r);
			keyd->next = dfi->keyd_file;
			dfi->keyd_file = keyd;
		}
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "new EF_KeyD file loaded (%d records)\n", recno - 1);
	/* FIXME: Do we need to restore the current DF?  I guess it is
	   not required, but we could try to do so by selecting 3fff?  */
	return 0;
}

/* Return the SE number from the keyD for the FID.  If ref_data is not
   NULL the reference data is returned; this shoudl be an array of at
   least 2 bytes.  Returns -1 on error.  */
static int get_se_num_from_keyd(sc_card_t * card, unsigned short fid,
				u8 * ref_data)
{
	sc_context_t *ctx = card->ctx;
	struct df_info_s *dfi;
	struct keyd_record_s *keyd;
	size_t len, taglen;
	const u8 *p, *tag;
	char dbgbuf[2048];
	u8 fidbuf[2];

	fidbuf[0] = (fid >> 8) & 0xFF;
	fidbuf[1] = fid & 0xFF;

	dfi = get_df_info(card);
	if (!dfi || !dfi->keyd_file) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "EF_keyD not loaded\n");
		return -1;
	}

	for (keyd = dfi->keyd_file; keyd; keyd = keyd->next) {
		p = keyd->data;
		len = keyd->datalen;

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL,
			p, len, dbgbuf, sizeof dbgbuf);
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "keyd no %d:\n%s", keyd->recno, dbgbuf);

		tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
		if (!tag || taglen != 4 ||
		    !(tag[2] == fidbuf[0] && tag[3] == fidbuf[1]))
			continue;
		/* Found a matching record. */
		if (ref_data) {
			ref_data[0] = tag[0];
			ref_data[1] = tag[1];
		}
		/* Look for the SE-DO */
		tag = sc_asn1_find_tag(ctx, p, len, 0x7B, &taglen);
		if (!tag || !taglen)
			continue;
		p = tag;
		len = taglen;
		/* And now look for the referenced SE. */
		tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
		if (!tag || taglen != 1)
			continue;
		return *tag;	/* found. */
	}
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "EF_keyD for %04hx not found\n", fid);
	return -1;
}

/* Process an ARR (7816-9/8.5.4) and setup the ACL. */
static void process_arr(sc_card_t * card, sc_file_t * file,
			const u8 * buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	struct df_info_s *dfi;
	struct rule_record_s *rule;
	size_t left, taglen;
	unsigned int cla, tag;
	const u8 *p;
	int skip;
	char dbgbuf[2048];

	/* Currently we support only the short for. */
	if (buflen != 1) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "can't handle long ARRs\n");
		return;
	}

	dfi = get_df_info(card);
	for (rule = dfi ? dfi->rule_file : NULL; rule && rule->recno != *buf;
	     rule = rule->next) ;
	if (!rule) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "referenced EF_rule record %d not found\n", *buf);
		return;
	}

	sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL,
		rule->data, rule->datalen, dbgbuf, sizeof dbgbuf);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		"rule for record %d:\n%s", *buf, dbgbuf);

	p = rule->data;
	left = rule->datalen;
	skip = 1;		/* Skip over initial unknown SC DOs. */
	for (;;) {
		buf = p;
		if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) !=
		    SC_SUCCESS)
			break;
		left -= (p - buf);
		tag |= cla;

		if (tag == 0x80 && taglen != 1) {
			skip = 1;
		} else if (tag == 0x80) {	/* AM byte. */
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "  AM_DO: %02x\n", *p);
			skip = 0;
		} else if (tag >= 0x81 && tag <= 0x8f) {	/* Cmd description */
			sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, p, taglen, dbgbuf, sizeof dbgbuf);
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "  AM_DO: cmd[%s%s%s%s] %s",
				 (tag & 8) ? "C" : "",
				 (tag & 4) ? "I" : "",
				 (tag & 2) ? "1" : "",
				 (tag & 1) ? "2" : "", dbgbuf);
			skip = 0;
		} else if (tag == 0x9C) {	/* Proprietary state machine descrip. */
			skip = 1;
		} else if (!skip) {
			sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, p, taglen, dbgbuf, sizeof dbgbuf);
			switch (tag) {
			case 0x90:	/* Always */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: always\n");
				break;
			case 0x97:	/* Never */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: never\n");
				break;
			case 0xA4:	/* Authentication, value is a CRT. */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: auth %s", dbgbuf);
				break;

			case 0xB4:
			case 0xB6:
			case 0xB8:	/* Cmd or resp with SM, value is a CRT. */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: cmd/resp %s", dbgbuf);
				break;

			case 0x9E:	/* Security Condition byte. */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: condition %s", dbgbuf);
				break;

			case 0xA0:	/* OR template. */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: OR\n");
				break;
			case 0xAF:	/* AND template. */
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "     SC: AND\n");
				break;
			}
		}
		left -= taglen;
		p += taglen;
	}

}

static void process_fcp(sc_card_t * card, sc_file_t * file,
			const u8 * buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;
	int bad_fde = 0;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "processing FCI bytes\n");

	/* File identifier. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"  file identifier: 0x%02X%02X\n", tag[0], tag[1]);
	}
	/* Number of data bytes in the file including structural information. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
	if (!tag) {
		/* My card does not encode the filelength in 0x81 but
		   in 0x85 which is the file descriptor extension in TCOS.
		   Assume that this is the case when the regular file
		   size tag is not encoded. */
		tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
		bad_fde = !!tag;
	}
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  bytes in file: %d\n", bytes);
			file->size = bytes;
		}
	}

	/* File descriptor byte(s). */
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		/* Fixme, this might actual be up to 6 bytes. */
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  shareable: %s\n",
				 (byte & 0x40) ? "yes" : "no");
			file->ef_structure = byte & 0x07;
			switch ((byte >> 3) & 7) {
			case 0:
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				break;
			case 1:
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				break;
			case 7:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			default:
				type = "unknown";
				break;
			}
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  type: %s\n", type);
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"  EF structure: %d\n", byte & 0x07);
		}
	}

	/* DF name. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char name[17];
		size_t i;

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		for (i = 0; i < taglen; i++) {
			if (isalnum(tag[i]) || ispunct(tag[i])
			    || isspace(tag[i]))
				name[i] = tag[i];
			else
				name[i] = '?';
		}
		name[taglen] = 0;
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "  file name: %s\n", name);
	}

	/* Proprietary information. */
	tag = bad_fde ? NULL : sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen);
	} else
		file->prop_attr_len = 0;

	/* Proprietary information, constructed. */
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen);
	}

	/* Security attributes, proprietary format. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_sec_attr(file, tag, taglen);
	}

	/* Security attributes, reference to expanded format. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x8B, &taglen);
	if (tag && taglen && !is_esteid_card(card)) {
		process_arr(card, file, tag, taglen);
	} else if ((tag = sc_asn1_find_tag(ctx, p, len, 0xA1, &taglen))
		   && taglen) {
		/* Not found, but there is a Security Attribute
		   Template for interface mode. */
		tag = sc_asn1_find_tag(ctx, tag, taglen, 0x8B, &taglen);
		if (tag && taglen)
			process_arr(card, file, tag, taglen);
	}

	file->magic = SC_FILE_MAGIC;
}

/* Send a select command and parse the response. */
static int
do_select(sc_card_t * card, u8 kind,
	  const u8 * buf, size_t buflen, sc_file_t ** file)
{
	sc_apdu_t apdu;
	u8 resbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	u8 p2 = 0x00;
	if (kind == MCRD_SEL_EF) p2 = 0x04;
	if (kind == MCRD_SEL_DF) p2 = 0x0C;

	sc_format_apdu(card, &apdu, buflen?SC_APDU_CASE_4_SHORT:SC_APDU_CASE_2_SHORT, 0xA4, kind, p2);
	apdu.data = buf;
	apdu.datalen = buflen;
	apdu.lc = apdu.datalen;
	apdu.resp = resbuf;
	apdu.resplen = sizeof(resbuf);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (!file) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (!r && kind == MCRD_SEL_AID)
			card->cache.current_path.len = 0;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (p2 == 0x0C) {
		if (file) {
			*file = sc_file_new();
			if (!*file)
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
			(*file)->type = SC_FILE_TYPE_DF;
			return SC_SUCCESS;
		}
	}

	if (p2 == 0x04 && apdu.resp[0] == 0x62) {
		*file = sc_file_new();
		if (!*file)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		/* EstEID v3.0 cards are buggy and sometimes return a double 0x62 tag */
		if (card->type == SC_CARD_TYPE_MCRD_ESTEID_V30 && apdu.resp[2] == 0x62)
			process_fcp(card, *file, apdu.resp + 4, apdu.resp[3]);
		else
			process_fcp(card, *file, apdu.resp + 2, apdu.resp[1]);
		return SC_SUCCESS;
	}

	if (p2 != 0x0C && apdu.resp[0] == 0x6F) {
		*file = sc_file_new();
		if (!*file)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		if (apdu.resp[1] <= apdu.resplen)
		process_fcp(card, *file, apdu.resp + 2, apdu.resp[1]);
		return SC_SUCCESS;
	}
	return SC_SUCCESS;
}

/* Wrapper around do_select to be used when multiple selects are
   required. */
static int
select_part(sc_card_t * card, u8 kind, unsigned short int fid,
	    sc_file_t ** file)
{
	u8 fbuf[2];
	unsigned int len;
	int r;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"select_part (0x%04X, kind=%u)\n", fid, kind);

	if (fid == MFID) {
		kind = MCRD_SEL_MF;	/* force this kind. */
		len = 0;
	} else {
		fbuf[0] = fid >> 8;
		fbuf[1] = fid & 0xff;
		len = 2;
	}
	r = do_select(card, kind, fbuf, len, file);

	return r;
}

/* Select a file by iterating over the FID in the PATHPTR array while
   updating the curpath kept in the private data cache.  With DF_ONLY
   passed as true only DF are selected, otherwise the function tries
   to figure out whether the last path item is a DF or EF. */
static int
select_down(sc_card_t * card,
	    unsigned short *pathptr, size_t pathlen,
	    int df_only, sc_file_t ** file)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	int r;
	int found_ef = 0;

	if (!pathlen)
		return SC_ERROR_INVALID_ARGUMENTS;

	for (; pathlen; pathlen--, pathptr++) {
		if (priv->curpathlen == MAX_CURPATH)
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL,
				    "path too long for cache");
		r = -1;		/* force DF select. */
		if (pathlen == 1 && !df_only) {
			/* first try to select an EF and retry an DF
			   on error. */
			r = select_part(card, MCRD_SEL_EF, *pathptr, file);
			if (!r)
				found_ef = 1;
		}
		if (r)
			r = select_part(card, MCRD_SEL_DF, *pathptr,
					pathlen == 1 ? file : NULL);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select DF");
		priv->curpath[priv->curpathlen] = *pathptr;
		priv->curpathlen++;
	}
	priv->is_ef = found_ef;
	if (!found_ef && !is_esteid_card(card))
		load_special_files(card);

	return 0;
}

/* Handle the selection case when a PATH is requested.  Our card does
   not support this addressing so we have to emulate it.  To keep the
   security status we should not unnecessary change the directory;
   this is accomplished be keeping track of the currently selected
   file.  Note that PATH is an array of PATHLEN file ids and not the
   usual sc_path structure. */

static int
select_file_by_path(sc_card_t * card, unsigned short *pathptr,
		    size_t pathlen, sc_file_t ** file)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	int r;
	size_t i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(!priv->curpathlen || priv->curpath[0] == MFID);

	if (pathlen && *pathptr == 0x3FFF) {
		pathlen--;
		pathptr++;
	}

	if (!pathlen || pathlen >= MAX_CURPATH)
		r = SC_ERROR_INVALID_ARGUMENTS;
	else if (pathlen == 1 && pathptr[0] == MFID) {
		/* MF requested: clear the cache and select it. */
		priv->curpathlen = 0;
		r = select_part(card, MCRD_SEL_MF, pathptr[0], file);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select MF");
		priv->curpath[0] = pathptr[0];
		priv->curpathlen = 1;
		priv->is_ef = 0;
	} else if (pathlen > 1 && pathptr[0] == MFID) {
		/* Absolute addressing, check cache to avoid
		   unnecessary selects. */
		for (i = 0; (i < pathlen && i < priv->curpathlen
			     && pathptr[i] == priv->curpath[i]); i++) ;
		if (!priv->curpathlen) {
			/* Need to do all selects starting at the root. */
			priv->curpathlen = 0;
			priv->is_ef = 0;
			r = select_down(card, pathptr, pathlen, 0, file);
		} else if (i == pathlen && i < priv->curpathlen) {
			/* Go upwards; we do it the easy way and start
			   at the root.  However we know that the target is a DF. */
			priv->curpathlen = 0;
			priv->is_ef = 0;
			r = select_down(card, pathptr, pathlen, 1, file);
		} else if (i == pathlen && i == priv->curpathlen) {
			/* Already selected. */
			if (!file)
				r = 0;	/* The caller did not request the fci. */
			else {
				/* This EF or DF was already selected, but
				   we need to get the FCI, so we have
				   to select again. */
				assert(priv->curpathlen > 1);
				priv->curpathlen--;
				priv->is_ef = 0;
				r = select_down(card, pathptr + pathlen - 1, 1,
						0, file);
			}
		} else {
			/* We have to append something.  For now we
			   simply start at the root. (fixme) */
			priv->curpathlen = 0;
			priv->is_ef = 0;
			r = select_down(card, pathptr, pathlen, 0, file);
		}
	} else {
		/* Relative addressing. */
		if (!priv->curpathlen) {
			/* Relative addressing without a current path. So we
			   select the MF first. */
			r = select_part(card, MCRD_SEL_MF, pathptr[0], file);
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select MF");
			priv->curpath[0] = pathptr[0];
			priv->curpathlen = 1;
			priv->is_ef = 0;
		}
		if (priv->is_ef) {
			assert(priv->curpathlen > 1);
			priv->curpathlen--;
			priv->is_ef = 0;
		}
		r = select_down(card, pathptr, pathlen, 0, file);
	}
	return r;
}

static int
select_file_by_fid(sc_card_t * card, unsigned short *pathptr,
		   size_t pathlen, sc_file_t ** file)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(!priv->curpathlen || priv->curpath[0] == MFID);

	if (pathlen > 1)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (pathlen && *pathptr == 0x3FFF)
		return 0;

	if (!pathlen) {
		/* re-select the current one if needed. */
		if (!file)
			r = 0;	/* The caller did not request the fci. */
		else if (!priv->curpathlen) {
			/* There is no current file. */
			r = SC_ERROR_INTERNAL;
		} else {
			assert(priv->curpathlen > 1);
			priv->curpathlen--;
			priv->is_ef = 0;
			r = select_down(card, pathptr, 1, 0, file);
		}
	} else if (pathptr[0] == MFID) {
		/* MF requested: clear the cache and select it. */
		priv->curpathlen = 0;
		r = select_part(card, MCRD_SEL_MF, MFID, file);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select MF");
		priv->curpath[0] = MFID;
		priv->curpathlen = 1;
		priv->is_ef = 0;
	} else {
		/* Relative addressing. */
		if (!priv->curpathlen) {
			/* Relative addressing without a current path. So we
			   select the MF first. */
			r = select_part(card, MCRD_SEL_MF, pathptr[0], file);
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select MF");
			priv->curpath[0] = pathptr[0];
			priv->curpathlen = 1;
			priv->is_ef = 0;
		}
		if (priv->is_ef) {
			assert(priv->curpathlen > 1);
			priv->curpathlen--;
			priv->is_ef = 0;
		}
		r = select_down(card, pathptr, 1, 0, file);
	}

	return r;
}

/* This drivers select command handler. */
static int
mcrd_select_file(sc_card_t * card, const sc_path_t * path, sc_file_t ** file)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	int r = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	{
		char line[256], *linep;
		size_t i;

		linep = line;
		linep += sprintf(linep, "ef=%d, curpath=", priv->is_ef);

		for (i = 0; i < priv->curpathlen; i++) {
			sprintf(linep, "%04X", priv->curpath[i]);
			linep += 4;
		}
		strcpy(linep, "\n");
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, line);
	}

	if (path->type == SC_PATH_TYPE_DF_NAME) {
		if (path->len > 16)
			return SC_ERROR_INVALID_ARGUMENTS;
		r = do_select(card, MCRD_SEL_AID, path->value, path->len, file);
		priv->curpathlen = 0;
	} else {
		unsigned short int pathtmp[SC_MAX_PATH_SIZE / 2];
		unsigned short int *pathptr;
		int samepath = 1;
		size_t pathlen, n;

		if ((path->len & 1) || path->len > sizeof(pathtmp))
			return SC_ERROR_INVALID_ARGUMENTS;

		pathptr = pathtmp;
		for (n = 0; n < path->len; n += 2)
			pathptr[n >> 1] =
			    (path->value[n] << 8) | path->value[n + 1];
		pathlen = path->len >> 1;

		if (pathlen == priv->curpathlen && priv->is_ef != 2) {
			for (n = 0; n < pathlen; n++) {
				if (priv->curpath[n] != pathptr[n]) {
					samepath = 0;
					break;
				}
			}
		} else if (priv->curpathlen < pathlen && priv->is_ef != 2) {
			for (n = 0; n < priv->curpathlen; n++) {
				if (priv->curpath[n] != pathptr[n]) {
					samepath = 0;
					break;
				}
			}
			pathptr = pathptr + n;
			pathlen = pathlen - n;
		}

		if (samepath != 1 || priv->is_ef == 0 || priv->is_ef == 1) {
			if (path->type == SC_PATH_TYPE_PATH)
				r = select_file_by_path(card, pathptr, pathlen,
							file);
			else {	/* SC_PATH_TYPE_FILEID */
				r = select_file_by_fid(card, pathptr, pathlen,
						       file);
			}
		}
	}

	{
		char line[256], *linep = line;
		size_t i;
		linep +=
		    sprintf(linep, "  result=%d, ef=%d, curpath=", r,
			    priv->is_ef);
		for (i = 0; i < priv->curpathlen; i++) {
			sprintf(linep, "%04X", priv->curpath[i]);
			linep += 4;
		}
		strcpy(linep, "\n");
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, line);
	}
	return r;
}

/* Crypto operations */
static int mcrd_restore_se(sc_card_t * card, int se_num)
{
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0xF3, se_num);
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


/* It seems that MICARDO does not fully comply with ISO, so I use
   values gathered from peeking actual signing opeations using a
   different system.
   It has been generalized [?] and modified by information coming from
   openpgp card implementation, EstEID 'manual' and some other sources. -mp
   */
static int mcrd_set_security_env(sc_card_t * card,
				 const sc_security_env_t * env, int se_num)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	sc_apdu_t apdu;
	sc_path_t tmppath;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	/* special environment handling for esteid, stolen from openpgp */
	if (is_esteid_card(card)) {
		/* some sanity checks */
		if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
			if (env->algorithm != SC_ALGORITHM_RSA)
				return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
		    || env->key_ref_len != 1)
			return SC_ERROR_INVALID_ARGUMENTS;

		/* Make sure we always start from MF */
		sc_format_path ("3f00", &tmppath);
		r = sc_select_file (card, &tmppath, NULL);
		if (r < 0)
			return r;
		/* We now know that cache is not valid */
		select_esteid_df(card);
		switch (env->operation) {
		case SC_SEC_OPERATION_DECIPHER:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Using keyref %d to dechiper\n",
				 env->key_ref[0]);
			mcrd_restore_se(card, 6);
			mcrd_delete_ref_to_authkey(card);
			mcrd_delete_ref_to_signkey(card);
			mcrd_set_decipher_key_ref(card, env->key_ref[0]);
			break;
		case SC_SEC_OPERATION_SIGN:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Using keyref %d to sign\n",
				 env->key_ref[0]);
			mcrd_restore_se(card, 1);
			break;
		default:
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		priv->sec_env = *env;
		return 0;
	}

	if (card->type == SC_CARD_TYPE_MCRD_DTRUST
	    || card->type == SC_CARD_TYPE_MCRD_GENERIC) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Using SC_CARD_TYPE_MCRD_DTRUST\n");
		/* some sanity checks */
		if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
			if (env->algorithm != SC_ALGORITHM_RSA)
				return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
		    || env->key_ref_len != 1)
			return SC_ERROR_INVALID_ARGUMENTS;

		switch (env->operation) {
		case SC_SEC_OPERATION_DECIPHER:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Using keyref %d to dechiper\n",
				 env->key_ref[0]);
			mcrd_delete_ref_to_authkey(card);
			mcrd_delete_ref_to_signkey(card);
			mcrd_set_decipher_key_ref(card, env->key_ref[0]);
			break;
		case SC_SEC_OPERATION_SIGN:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Using keyref %d to sign\n",
				 env->key_ref[0]);
			break;
		default:
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		priv->sec_env = *env;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	apdu.le = 0;
	p = sbuf;
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	*p++ = 0x83;
	*p++ = 0x03;
	*p++ = 0x80;

	if (card->type == SC_CARD_TYPE_MCRD_DTRUST
	    || card->type == SC_CARD_TYPE_MCRD_GENERIC) {
		unsigned char fid;

		fid = env->key_ref[0];
		*p = fid;
		p++;
		*p = 0;
		p++;
	} else if (is_esteid_card(card)) {
		if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
		    && env->file_ref.len > 1) {
			unsigned short fid;
			int num;

			fid = env->file_ref.value[env->file_ref.len - 2] << 8;
			fid |= env->file_ref.value[env->file_ref.len - 1];
			num = get_se_num_from_keyd(card, fid, p);
			if (num != -1) {
				/* Need to restore the security environmnet. */
				if (num) {
					r = mcrd_restore_se(card, num);
					SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,
						    "mcrd_enable_se failed");
				}
				p += 2;
			}
		}
	} else {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (se_num > 0) {
		r = sc_lock(card);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_unlock(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
      err:
	if (locked)
		sc_unlock(card);
	return r;
}

/* heavily modified by -mp */
static int mcrd_compute_signature(sc_card_t * card,
				  const u8 * data, size_t datalen,
				  u8 * out, size_t outlen)
{
	struct mcrd_priv_data *priv = DRVDATA(card);
	sc_security_env_t *env = &priv->sec_env;
	int r;
	sc_apdu_t apdu;

	assert(card != NULL && data != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Will compute signature (%d) for %d (0x%02x) bytes using key %d algorithm %d flags %d\n",
		 env->operation, datalen, datalen, env->key_ref[0],
		 env->algorithm, env->algorithm_flags);

	switch (env->key_ref[0]) {
	case SC_ESTEID_AUTH:	/* authentication key */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0, 0);
		break;
	default:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT,
			       0x2A, 0x9E, 0x9A);

	}
	apdu.lc = datalen;
	apdu.data = data;
	apdu.datalen = datalen;
	apdu.le = 0x80;
	apdu.resp = out;
	apdu.resplen = outlen;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
}

/* added by -mp, to give pin information in the card driver (pkcs15emu->driver needed) */
static int mcrd_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data *data,
			int *tries_left)
{
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	data->pin1.offset = 5;
	data->pin1.length_offset = 4;
	data->pin2.offset = 5;
	data->pin2.length_offset = 4;

	if (is_esteid_card(card) && data->cmd == SC_PIN_CMD_GET_INFO) {
		sc_path_t tmppath;
		u8 buf[16];
		int ref_to_record[] = {3,1,2};

		/* the file with key pin info (tries left) 4.5 EF_PwdC */
		/* XXX: cheat the file path cache by always starting fresh from MF */
		sc_format_path ("3f00", &tmppath);
		r = sc_select_file (card, &tmppath, NULL);
		if (r < 0)
			return SC_ERROR_INTERNAL;

		sc_format_path ("3f000016", &tmppath);
		r = sc_select_file (card, &tmppath, NULL);
		if (r < 0)
			return SC_ERROR_INTERNAL;

		/* read the number of tries left for the PIN */
		r = sc_read_record (card, ref_to_record[data->pin_reference], buf, sizeof(buf), SC_RECORD_BY_REC_NR);
		if (r < 0)
			return SC_ERROR_INTERNAL;
		if (buf[0] != 0x80 || buf[3] != 0x90)
			return SC_ERROR_INTERNAL;
		data->pin1.tries_left = buf[5];
		data->pin1.max_tries = buf[2];
		data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
		return SC_SUCCESS;
	}

	if (card->type == SC_CARD_TYPE_MCRD_DTRUST
	    || card->type == SC_CARD_TYPE_MCRD_GENERIC) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "modify pin reference for D-Trust\n");
		if (data->pin_reference == 0x02)
			data->pin_reference = data->pin_reference | 0x80;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, iso_ops->pin_cmd(card, data, tries_left));
}

/* Driver binding */
static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	mcrd_ops = *iso_drv->ops;
	mcrd_ops.match_card = mcrd_match_card;
	mcrd_ops.init = mcrd_init;
	mcrd_ops.finish = mcrd_finish;
	mcrd_ops.select_file = mcrd_select_file;
	mcrd_ops.set_security_env = mcrd_set_security_env;
	mcrd_ops.compute_signature = mcrd_compute_signature;
	mcrd_ops.pin_cmd = mcrd_pin_cmd;

	return &mcrd_drv;
}

struct sc_card_driver *sc_get_mcrd_driver(void)
{
	return sc_get_driver();
}
