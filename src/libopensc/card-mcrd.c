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
#include "gp.h"

static const struct sc_atr_table mcrd_atrs[] = {
	{"3B:FF:94:00:FF:80:B1:FE:45:1F:03:00:68:D2:76:00:00:28:FF:05:1E:31:80:00:90:00:23", NULL,
	  "Micardo 2.1/German BMI/D-Trust", SC_CARD_TYPE_MCRD_GENERIC, 0, NULL},
	{"3b:6f:00:ff:00:68:d2:76:00:00:28:ff:05:1e:31:80:00:90:00", NULL,
	  "D-Trust", SC_CARD_TYPE_MCRD_GENERIC, 0, NULL},
	{"3b:ff:11:00:ff:80:b1:fe:45:1f:03:00:68:d2:76:00:00:28:ff:05:1e:31:80:00:90:00:a6", NULL,
	  "D-Trust", SC_CARD_TYPE_MCRD_GENERIC, 0, NULL},
	{"3B:FE:18:00:00:80:31:FE:45:45:73:74:45:49:44:20:76:65:72:20:31:2E:30:A8", NULL, "EstEID 3.0 (dev1) cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3B:FE:18:00:00:80:31:FE:45:80:31:80:66:40:90:A4:56:1B:16:83:01:90:00:86", NULL, "EstEID 3.0 (dev1) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fe:18:00:00:80:31:fe:45:80:31:80:66:40:90:a4:16:2a:00:83:01:90:00:e1", NULL, "EstEID 3.0 (dev2) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fe:18:00:00:80:31:fe:45:80:31:80:66:40:90:a4:16:2a:00:83:0f:90:00:ef", NULL, "EstEID 3.0 (18.01.2011) warm", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL},
	{"3b:fa:18:00:00:80:31:fe:45:fe:65:49:44:20:2f:20:50:4b:49:03", NULL, "EstEID 3.5 cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL },
	{"3b:f8:18:00:00:80:31:fe:45:fe:41:5a:45:20:44:49:54:33", NULL, "AzeDIT 3.5 cold", SC_CARD_TYPE_MCRD_ESTEID_V30, 0, NULL },
	{NULL, NULL, NULL, 0, 0, NULL}
};

static const struct sc_aid EstEID_v35_AID = { {0xD2, 0x33, 0x00, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x33, 0x35}, 15 };

static struct sc_card_operations mcrd_ops;
static struct sc_card_driver mcrd_drv = {
	"MICARDO 2.1 / EstEID 3.0 - 3.5",
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
#define SC_ESTEID_KEYREF_FILE_RECLEN 21

#define MAX_CURPATH 10

struct rule_record_s {
	struct rule_record_s *next;
	unsigned int recno;
	size_t datalen;
	u8 data[1];
};

struct keyd_record_s {
	struct keyd_record_s *next;
	unsigned int recno;
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
	int is_ef;		/* True if the path points to an EF. */
	size_t curpathlen;	/* Length of this path or 0 if unknown. */
	struct df_info_s *df_infos;
	sc_security_env_t sec_env;	/* current security environment */
};

#define DRVDATA(card) ((struct mcrd_priv_data *) ((card)->drv_data))

// Control Reference Template Tag for Key Agreement (ISO 7816-4:2013 Table 54)
static const struct sc_asn1_entry c_asn1_control[] = {
	{ "control", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_CTX | 0xA6, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

// Ephemeral public key Template Tag (ISO 7816-8:2016 Table 3)
static const struct sc_asn1_entry c_asn1_ephermal[] = {
	{ "ephemeral", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x7F49, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

// External Public Key
static const struct sc_asn1_entry c_asn1_public[] = {
	{ "publicKey", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x86, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int load_special_files(sc_card_t * card);
static int select_part(sc_card_t * card, u8 kind, unsigned short int fid, sc_file_t ** file);

/* Return the DF_info for the current path.  If does not yet exist,
   create it.  Returns NULL on error. */
static struct df_info_s *get_df_info(sc_card_t * card)
{
	sc_context_t *ctx = card->ctx;
	struct mcrd_priv_data *priv = DRVDATA(card);
	struct df_info_s *dfi;

	if(!(!priv->is_ef))
		return NULL;

	if (!priv->curpathlen) {
		sc_log(ctx, "no current path to find the df_info\n");
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
		sc_log(ctx, "out of memory while allocating df_info\n");
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
	u8 sbuf[2] = { 0x83, 0x00 };
	if(card == NULL)
		return SC_ERROR_INTERNAL;
	sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xA4, sbuf, 2, NULL, 0);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int mcrd_delete_ref_to_signkey(sc_card_t * card)
{
	sc_apdu_t apdu;
	int r;
	u8 sbuf[2] = { 0x83, 0x00 };
	if(card == NULL)
		return SC_ERROR_INTERNAL;
	sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6, sbuf, 2, NULL, 0);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int is_esteid_card(sc_card_t *card)
{
	return card->type == SC_CARD_TYPE_MCRD_ESTEID_V30 ? 1 : 0;
}

static int mcrd_match_card(sc_card_t * card)
{
	int i = 0, r = 0;

	i = _sc_match_atr(card, mcrd_atrs, &card->type);
	if (i >= 0) {
		card->name = mcrd_atrs[i].name;
		return 1;
	}

	LOG_FUNC_CALLED(card->ctx);
	r = gp_select_aid(card, &EstEID_v35_AID);
	if (r >= 0) {
		sc_log(card->ctx, "AID found");
		card->type = SC_CARD_TYPE_MCRD_ESTEID_V30;
		return 1;
	}
	return 0;
}

static int mcrd_init(sc_card_t * card)
{
	unsigned long flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE, ext_flags;
	struct mcrd_priv_data *priv = calloc(1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	priv->curpath[0] = MFID;
	priv->curpathlen = 1;
	card->drv_data = priv;
	card->cla = 0x00;
	card->caps = SC_CARD_CAP_RNG;

	if (is_esteid_card(card)) {
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;
		_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);
		// Force EstEID 3.5 card recv size 255 with T=0 to avoid recursive read binary
		// sc_read_binary cannot handle recursive 61 00 calls
		if (card->reader && card->reader->active_protocol == SC_PROTO_T0)
			card->max_recv_size = 255;
	} else {
		_sc_card_add_rsa_alg(card, 512, flags, 0);
		_sc_card_add_rsa_alg(card, 768, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
	}

	if (SC_SUCCESS != sc_select_file (card, sc_get_mf_path(), NULL))
		sc_log(card->ctx, "Warning: select MF failed");

	/* Not needed for the fixed EstEID profile */
	if (!is_esteid_card(card))
		load_special_files(card);

	return SC_SUCCESS;
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
		free(priv->df_infos);
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
	int r;
	unsigned int recno;
	struct df_info_s *dfi;
	struct rule_record_s *rule;
	struct keyd_record_s *keyd;

	/* First check whether we already cached it. */
	dfi = get_df_info(card);
	if (dfi && dfi->rule_file)
		return 0;	/* yes. */
	clear_special_files(dfi);
	if (!dfi)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	/* Read rule file. Note that we bypass our cache here. */
	r = select_part(card, MCRD_SEL_EF, EF_Rule, NULL);
	LOG_TEST_RET(ctx, r, "selecting EF_Rule failed");

	for (recno = 1;; recno++) {
		u8 recbuf[256];
		r = sc_read_record(card, recno, recbuf, sizeof(recbuf),
					SC_RECORD_BY_REC_NR);

		if (r == SC_ERROR_RECORD_NOT_FOUND)
			break;
		if (r < 0) {
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		} else {
			rule = malloc(sizeof *rule + (size_t)r);
			if (!rule)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			rule->recno = recno;
			rule->datalen = (size_t)r;
			memcpy(rule->data, recbuf, r);
			rule->next = dfi->rule_file;
			dfi->rule_file = rule;
		}
	}

	sc_log(ctx, "new EF_Rule file loaded (%d records)\n", recno - 1);

	/* Read the KeyD file. Note that we bypass our cache here. */
	r = select_part(card, MCRD_SEL_EF, EF_KeyD, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_log(ctx, "no EF_KeyD file available\n");
		return 0;	/* That is okay. */
	}
	LOG_TEST_RET(ctx, r, "selecting EF_KeyD failed");

	for (recno = 1;; recno++) {
		u8 recbuf[256];
		r = sc_read_record(card, recno, recbuf, sizeof(recbuf),
					SC_RECORD_BY_REC_NR);

		if (r == SC_ERROR_RECORD_NOT_FOUND)
			break;
		if (r < 0) {
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		} else {
			keyd = malloc(sizeof *keyd + (size_t)r);
			if (!keyd)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			keyd->recno = recno;
			keyd->datalen = (size_t) r;
			memcpy(keyd->data, recbuf, r);
			keyd->next = dfi->keyd_file;
			dfi->keyd_file = keyd;
		}
	}

	sc_log(ctx, "new EF_KeyD file loaded (%d records)\n", recno - 1);
	/* FIXME: Do we need to restore the current DF?  I guess it is
	   not required, but we could try to do so by selecting 3fff?  */
	return 0;
}

/* Process an ARR (7816-9/8.5.4) and setup the ACL. */
static void process_arr(sc_card_t * card, const u8 * buf, size_t buflen)
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
		sc_log(ctx, "can't handle long ARRs\n");
		return;
	}

	dfi = get_df_info(card);
	for (rule = dfi ? dfi->rule_file : NULL; rule && rule->recno != *buf;
		rule = rule->next) ;
	if (!rule) {
		sc_log(ctx, "referenced EF_rule record %d not found\n", *buf);
		return;
	}

	sc_hex_dump(rule->data, rule->datalen, dbgbuf, sizeof dbgbuf);
	sc_log(ctx,
		"rule for record %d:\n%s", *buf, dbgbuf);

	p = rule->data;
	left = rule->datalen;
	skip = 1;		/* Skip over initial unknown SC DOs. */
	for (;;) {
		buf = p;
		if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) != SC_SUCCESS
				|| p == NULL)
			break;
		left -= (size_t)(p - buf);
		tag |= cla;

		if (tag == 0x80 && taglen != 1) {
			skip = 1;
		} else if (tag == 0x80) {	/* AM byte. */
			sc_log(ctx, "  AM_DO: %02x\n", *p);
			skip = 0;
		} else if (tag >= 0x81 && tag <= 0x8f) {	/* Cmd description */
			sc_hex_dump(p, taglen, dbgbuf, sizeof dbgbuf);
			sc_log(ctx, "  AM_DO: cmd[%s%s%s%s] %s",
				 (tag & 8) ? "C" : "",
				 (tag & 4) ? "I" : "",
				 (tag & 2) ? "1" : "",
				 (tag & 1) ? "2" : "", dbgbuf);
			skip = 0;
		} else if (tag == 0x9C) {	/* Proprietary state machine descrip. */
			skip = 1;
		} else if (!skip) {
			switch (tag) {
			case 0x90:	/* Always */
				sc_log(ctx, "     SC: always\n");
				break;
			case 0x97:	/* Never */
				sc_log(ctx, "     SC: never\n");
				break;
			case 0xA4:	/* Authentication, value is a CRT. */
				sc_log_hex(ctx, "     SC: auth", p, taglen);
				break;

			case 0xB4:
			case 0xB6:
			case 0xB8:	/* Cmd or resp with SM, value is a CRT. */
				sc_log_hex(ctx, "     SC: cmd/resp", p, taglen);
				break;

			case 0x9E:	/* Security Condition byte. */
				sc_log_hex(ctx, "     SC: condition", p, taglen);
				break;

			case 0xA0:	/* OR template. */
				sc_log(ctx, "     SC: OR\n");
				break;
			case 0xAF:	/* AND template. */
				sc_log(ctx, "     SC: AND\n");
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

	sc_log(ctx, "processing FCI bytes\n");

	/* File identifier. */
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(ctx,
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
		sc_log(ctx,
			"  bytes in file: %d\n", bytes);
		file->size = (size_t)bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			sc_log(ctx,
				"  bytes in file: %d\n", bytes);
			file->size = (size_t)bytes;
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
			sc_log(ctx,
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
			sc_log(ctx,
				"  type: %s\n", type);
			sc_log(ctx,
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
			if (isalnum(tag[i]) || ispunct(tag[i]) || isspace(tag[i]))
				name[i] = (const char)tag[i];
			else
				name[i] = '?';
		}
		name[taglen] = 0;
		sc_log(ctx, "  file name: %s\n", name);
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
		process_arr(card, tag, taglen);
	} else if ((tag = sc_asn1_find_tag(ctx, p, len, 0xA1, &taglen))
			&& taglen) {
		/* Not found, but there is a Security Attribute
		   Template for interface mode. */
		tag = sc_asn1_find_tag(ctx, tag, taglen, 0x8B, &taglen);
		if (tag && taglen)
			process_arr(card, tag, taglen);
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

	sc_format_apdu_ex(&apdu, 0x00, 0xA4, kind, p2, buf, buflen, resbuf, 256);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
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
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			(*file)->type = SC_FILE_TYPE_DF;
			return SC_SUCCESS;
		}
	}

	if (p2 == 0x04 && apdu.resp[0] == 0x62) {
		*file = sc_file_new();
		if (!*file)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
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
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
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

	sc_log(card->ctx,
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
			LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL,
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
		LOG_TEST_RET(card->ctx, r, "unable to select DF");
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

	if (!(!priv->curpathlen || priv->curpath[0] == MFID))
		return SC_ERROR_INTERNAL;

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
		LOG_TEST_RET(card->ctx, r, "unable to select MF");
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
				if (!(priv->curpathlen > 1))
					return SC_ERROR_INTERNAL;
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
			LOG_TEST_RET(card->ctx, r, "unable to select MF");
			priv->curpath[0] = pathptr[0];
			priv->curpathlen = 1;
			priv->is_ef = 0;
		}
		if (priv->is_ef) {
			if(!(priv->curpathlen > 1))
				return SC_ERROR_INTERNAL;
			priv->curpathlen--;
			priv->is_ef = 0;
		}
		/* Free the previously allocated file so we do not leak memory here */
		if (file) {
			sc_file_free(*file);
			*file = NULL;
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

	if (!(!priv->curpathlen || priv->curpath[0] == MFID))
		return SC_ERROR_INTERNAL;

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
			if (!(priv->curpathlen > 1))
				return SC_ERROR_INTERNAL;
			priv->curpathlen--;
			priv->is_ef = 0;
			r = select_down(card, pathptr, 1, 0, file);
		}
	} else if (pathptr[0] == MFID) {
		/* MF requested: clear the cache and select it. */
		priv->curpathlen = 0;
		r = select_part(card, MCRD_SEL_MF, MFID, file);
		LOG_TEST_RET(card->ctx, r, "unable to select MF");
		priv->curpath[0] = MFID;
		priv->curpathlen = 1;
		priv->is_ef = 0;
	} else {
		/* Relative addressing. */
		if (!priv->curpathlen) {
			/* Relative addressing without a current path. So we
			   select the MF first. */
			r = select_part(card, MCRD_SEL_MF, pathptr[0], file);
			LOG_TEST_RET(card->ctx, r, "unable to select MF");
			priv->curpath[0] = pathptr[0];
			priv->curpathlen = 1;
			priv->is_ef = 0;
		}
		if (priv->is_ef) {
			if (!(priv->curpathlen > 1))
				return SC_ERROR_INTERNAL;
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

		memset(pathtmp, 0, sizeof pathtmp);
		pathptr = pathtmp;
		for (n = 0; n < path->len; n += 2)
			pathptr[n >> 1] =
				(unsigned short)((path->value[n] << 8) | path->value[n + 1]);
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
				r = select_file_by_path(card, pathptr, pathlen, file);
			else {	/* SC_PATH_TYPE_FILEID */
				r = select_file_by_fid(card, pathptr, pathlen, file);
			}
		}
	}

	return r;
}

/* It seems that MICARDO does not fully comply with ISO, so I use
   values gathered from peeking actual signing operations using a
   different system.
   It has been generalized [?] and modified by information coming from
   openpgp card implementation, EstEID 'manual' and some other sources. -mp
   */
static int mcrd_set_security_env(sc_card_t * card,
				 const sc_security_env_t * env, int se_num)
{
	struct mcrd_priv_data *priv;
	sc_apdu_t apdu;
	u8 sbuf[5];
	u8 *p;
	int r = 0, locked = 0;

	if (card == NULL || env == NULL)
		return SC_ERROR_INTERNAL;
	LOG_FUNC_CALLED(card->ctx);
	priv = DRVDATA(card);

	/* some sanity checks */
	if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
		if (env->algorithm != SC_ALGORITHM_RSA &&
			(is_esteid_card(card) && env->algorithm != SC_ALGORITHM_EC))
			return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
		|| env->key_ref_len != 1)
		return SC_ERROR_INVALID_ARGUMENTS;

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_DERIVE:
		sc_log(card->ctx, "Using keyref %d to decipher\n", env->key_ref[0]);
		mcrd_delete_ref_to_authkey(card);
		mcrd_delete_ref_to_signkey(card);
		break;
	case SC_SEC_OPERATION_SIGN:
		sc_log(card->ctx, "Using keyref %d to sign\n", env->key_ref[0]);
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	priv->sec_env = *env;
	if (is_esteid_card(card)) {
		return 0;
	}

	p = sbuf;
	*p++ = 0x83;
	*p++ = 0x03;
	*p++ = 0x80;
	*p++ = env->key_ref[0];
	*p++ = 0;
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_DERIVE:
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB8, sbuf, 5, NULL, 0);
		break;
	case SC_SEC_OPERATION_SIGN:
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6, sbuf, 5, NULL, 0);
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (se_num > 0) {
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_log(card->ctx,
				"%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_log(card->ctx,
				"%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
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
	sc_security_env_t *env = NULL;
	int r;
	sc_apdu_t apdu;

	if (data == NULL || out == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	env = &priv->sec_env;

	LOG_FUNC_CALLED(card->ctx);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(card->ctx,
		 "Will compute signature (%d) for %"SC_FORMAT_LEN_SIZE_T"u (0x%02"SC_FORMAT_LEN_SIZE_T"x) bytes using key %d algorithm %d flags %d\n",
		 env->operation, datalen, datalen, env->key_ref[0],
		 env->algorithm, env->algorithm_flags);

	if (env->key_ref[0] == 1) /* authentication key */
		sc_format_apdu_ex(&apdu, 0x00, 0x88, 0, 0, data, datalen, out, MIN(0x80U, outlen));
	else
		sc_format_apdu_ex(&apdu, 0x00, 0x2A, 0x9E, 0x9A, data, datalen, out, MIN(0x80U, outlen));
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, (int)apdu.resplen);
}

static int mcrd_decipher(struct sc_card *card,
						 const u8 * crgram, size_t crgram_len,
						 u8 * out, size_t outlen)
{
	sc_security_env_t *env = NULL;
	int r = 0;
	size_t sbuf_len = 0;
	sc_apdu_t apdu;
	u8 *sbuf = NULL;
	struct sc_asn1_entry asn1_control[2], asn1_ephermal[2], asn1_public[2];

	if (card == NULL || crgram == NULL || out == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	env = &DRVDATA(card)->sec_env;

	LOG_FUNC_CALLED(card->ctx);
	if (env->operation != SC_SEC_OPERATION_DERIVE)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, iso_ops->decipher(card, crgram, crgram_len, out, outlen));
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(card->ctx, 
		 "Will derive (%d) for %"SC_FORMAT_LEN_SIZE_T"u (0x%02"SC_FORMAT_LEN_SIZE_T"x) bytes using key %d algorithm %d flags %d\n",
		 env->operation, crgram_len, crgram_len, env->key_ref[0],
		 env->algorithm, env->algorithm_flags);

	// Encode TLV
	sc_copy_asn1_entry(c_asn1_control, asn1_control);
	sc_copy_asn1_entry(c_asn1_ephermal, asn1_ephermal);
	sc_copy_asn1_entry(c_asn1_public, asn1_public);
	sc_format_asn1_entry(asn1_public + 0, (void*)crgram, &crgram_len, 1);
	sc_format_asn1_entry(asn1_ephermal + 0, &asn1_public, NULL, 1);
	sc_format_asn1_entry(asn1_control + 0, &asn1_ephermal, NULL, 1);
	r = sc_asn1_encode(card->ctx, asn1_control, &sbuf, &sbuf_len);
	LOG_TEST_RET(card->ctx, r, "Error encoding TLV.");

	// Create APDU
	sc_format_apdu_ex(&apdu, 0x00, 0x2A, 0x80, 0x86, sbuf, sbuf_len, out, MIN(0x80U, outlen));
	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sbuf_len);
	free(sbuf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, (int)apdu.resplen);
}

/* added by -mp, to give pin information in the card driver (pkcs15emu->driver needed) */
static int mcrd_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data *data,
			int *tries_left)
{
	int r;
	LOG_FUNC_CALLED(card->ctx);
	data->pin1.offset = 5;
	data->pin2.offset = 5;

	if (is_esteid_card(card) && data->cmd == SC_PIN_CMD_GET_INFO) {
		sc_path_t tmppath;
		u8 buf[16];
		unsigned int ref_to_record[] = {3,1,2};

		/* the file with key pin info (tries left) 4.5 EF_PwdC */
		/* XXX: cheat the file path cache by always starting fresh from MF */
		r = sc_select_file (card, sc_get_mf_path(), NULL);
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

	if (card->type == SC_CARD_TYPE_MCRD_GENERIC) {
		sc_log(card->ctx, "modify pin reference for D-Trust\n");
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
	mcrd_ops.decipher = mcrd_decipher;
	mcrd_ops.pin_cmd = mcrd_pin_cmd;

	return &mcrd_drv;
}

struct sc_card_driver *sc_get_mcrd_driver(void)
{
	return sc_get_driver();
}
