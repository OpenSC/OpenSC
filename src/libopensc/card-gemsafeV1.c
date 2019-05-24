/*
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

/* Initially written by David Mattes (david.mattes@boeing.com) */
/* Portuguese eID card support by Joao Poupino (joao.poupino@ist.utl.pt) */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

#define GEMSAFEV1_ALG_REF_FREEFORM	0x12
#define GEMSAFEV3_ALG_REF_FREEFORM	0x02
#define GEMSAFEV3_ALG_REF_SHA1		0x12
#define GEMSAFEV3_ALG_REF_SHA256	0x42

static struct sc_card_operations gemsafe_ops;
static struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver gemsafe_drv = {
	"Gemalto GemSafe V1 applet",
	"gemsafeV1",
	&gemsafe_ops,
	NULL, 0, NULL
};

/* Known ATRs */
static const struct sc_atr_table gemsafe_atrs[] = {
	/* standard version */
    {"3B:7B:94:00:00:80:65:B0:83:01:01:74:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    {"3B:6B:00:00:80:65:B0:83:01:01:74:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    /* GemSafeXpresso 32K */
    {"3b:6d:00:00:80:31:80:65:b0:83:01:02:90:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    /* fips 140 version */
    {"3B:6B:00:00:80:65:B0:83:01:03:74:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    /* Undefined */
    {"3B:7A:94:00:00:80:65:A2:01:01:01:3D:72:D6:43", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    {"3B:7D:94:00:00:80:31:80:65:B0:83:01:01:90:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    {"3B:7D:96:00:00:80:31:80:65:B0:83:11:48:C8:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_GENERIC, 0, NULL},
    /* Portuguese eID cards */
    {"3B:7D:95:00:00:80:31:80:65:B0:83:11:C0:A9:83:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    {"3B:7D:95:00:00:80:31:80:65:B0:83:11:C0:A9:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    {"3B:7D:95:00:00:80:31:80:65:B0:83:11:00:C8:83:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    {"3B:7D:95:00:00:80:31:80:65:B0:83:11:00:C8:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    {"3B:FF:96:00:00:81:31:80:43:80:31:80:65:B0:85:03:00:EF:12:0F:FF:82:90:00:67", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    {"3B:FF:96:00:00:81:31:FE:43:80:31:80:65:B0:85:04:01:20:12:0F:FF:82:90:00:D0", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_PTEID, 0, NULL},
    /* Swedish eID card */
    {"3B:7D:96:00:00:80:31:80:65:B0:83:11:00:C8:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_SEEID, 0, NULL},
    /* European Patent Office epoline card*/
    {"3b:7d:96:00:00:80:31:80:65:b0:83:02:01:f3:83:00:90:00", NULL, NULL, SC_CARD_TYPE_GEMSAFEV1_SEEID, 0, NULL},
    {NULL, NULL, NULL, 0, 0, NULL}
};

static const u8 gemsafe_def_aid[] = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x0A,
	0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

static const u8 gemsafe_pteid_aid[] = {0x60, 0x46, 0x32, 0xFF, 0x00, 0x00, 0x02};

static const u8 gemsafe_seeid_aid[] = {0xA0, 0x00, 0x00, 0x00, 0x18, 0x0C,
                                       0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

/*
static const u8 gemsafe_def_aid[] = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
	0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
*/

typedef struct gemsafe_exdata_st {
	u8	aid[16];
	size_t	aid_len;
} gemsafe_exdata;

static int get_conf_aid(sc_card_t *card, u8 *aid, size_t *len)
{
	sc_context_t		*ctx = card->ctx;
	scconf_block		*conf_block, **blocks;
	int			i;
	const char		*str_aid;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	conf_block = NULL;
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
						"card", "gemsafeV1");
		if (blocks != NULL && blocks[0] != NULL)
			conf_block = blocks[0];
		free(blocks);
	}

	if (!conf_block) {
		sc_log(ctx,  "no card specific options configured, trying default AID\n");
		return SC_ERROR_INTERNAL;
	}

	str_aid = scconf_get_str(conf_block, "aid", NULL);
	if (!str_aid) {
		sc_log(ctx,  "no aid configured, trying default AID\n");
		return SC_ERROR_INTERNAL;
	}
	return sc_hex_to_bin(str_aid, aid, len);
}

static int gp_select_applet(sc_card_t *card, const u8 *aid, size_t aid_len)
{
	int	r;
	u8	buf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_context *ctx = card->ctx;
	struct sc_apdu    apdu;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xa4, 0x04, 0x00);
	apdu.lc      = aid_len;
	apdu.data    = aid;
	apdu.datalen = aid_len;
	apdu.resp    = buf;
	apdu.le      = 256;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);

	return SC_SUCCESS;
}

static int gemsafe_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, gemsafe_atrs, &card->type);
	if (i < 0)
		return 0;

	return 1;
}

static int gemsafe_init(struct sc_card *card)
{
	int	r;
	gemsafe_exdata *exdata = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->name = "GemSAFE V1";
	card->cla  = 0x00;

	exdata = (gemsafe_exdata *)calloc(1, sizeof(gemsafe_exdata));
	if (!exdata)
		return SC_ERROR_OUT_OF_MEMORY;
	exdata->aid_len = sizeof(exdata->aid);
	if(card->type == SC_CARD_TYPE_GEMSAFEV1_GENERIC) {
		/* try to get a AID from the config file */
		r = get_conf_aid(card, exdata->aid, &exdata->aid_len);
		if (r < 0) {
			/* failed, use default value */
			memcpy(exdata->aid, gemsafe_def_aid, sizeof(gemsafe_def_aid));
			exdata->aid_len = sizeof(gemsafe_def_aid);
		}
	} else if (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID) {
		memcpy(exdata->aid, gemsafe_pteid_aid, sizeof(gemsafe_pteid_aid));
		exdata->aid_len = sizeof(gemsafe_pteid_aid);
	} else if (card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) {
		memcpy(exdata->aid, gemsafe_seeid_aid, sizeof(gemsafe_seeid_aid));
		exdata->aid_len = sizeof(gemsafe_seeid_aid);
	}

	/* increase lock_count here to prevent sc_unlock to select
	 * applet twice in gp_select_applet */
	card->lock_count++;
	/* SELECT applet */
	r = gp_select_applet(card, exdata->aid, exdata->aid_len);
	if (r < 0) {
		free(exdata);
		sc_log(card->ctx,  "applet selection failed\n");
		return SC_ERROR_INVALID_CARD;
	}
	card->lock_count--;

	/* set the supported algorithm */
	r = gemsafe_match_card(card);
	if (r > 0) {
		unsigned long flags;

		flags  = SC_ALGORITHM_RSA_PAD_PKCS1;
		flags |= SC_ALGORITHM_RSA_PAD_ISO9796;
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
		flags |= SC_ALGORITHM_RSA_HASH_NONE;

		/* GemSAFE V3 cards support SHA256 */
		if (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
		    card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID)
			flags |= SC_ALGORITHM_RSA_HASH_SHA256;

		_sc_card_add_rsa_alg(card,  512, flags, 0);
		_sc_card_add_rsa_alg(card,  768, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);

		/* fake algorithm to persuade register_mechanisms()
		 * to register these hashes */
		if (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
		    card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) {
			flags  = SC_ALGORITHM_RSA_HASH_SHA1;
			flags |= SC_ALGORITHM_RSA_HASH_MD5;
			flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;

			_sc_card_add_rsa_alg(card,  512, flags, 0);
		}
	}

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;
	card->drv_data = exdata;

	return SC_SUCCESS;
}

static int gemsafe_finish(sc_card_t *card)
{
	gemsafe_exdata *exdata = (gemsafe_exdata *)card->drv_data;

	if (exdata)
		free(exdata);
	return SC_SUCCESS;
}

static int gemsafe_select_file(struct sc_card *card, const struct sc_path *path,
	   struct sc_file **file_out)
{
	/* so far just call the iso select file (but this will change) */
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	return iso_ops->select_file(card, path, file_out);
}

static int gemsafe_sc2acl(sc_file_t *file, unsigned ops, u8 sc_byte)
{
	int r;
	unsigned int meth = 0;

	if (sc_byte == 0xff) {
		r = sc_file_add_acl_entry(file, ops, SC_AC_NEVER, 0);
		return r;
	}
	if (sc_byte == 0x00) {
		r = sc_file_add_acl_entry(file, ops, SC_AC_NONE, 0);
		return r;
	}

	/* XXX: OR combination of access rights are currently not supported
	 * hence ignored */
	if (sc_byte & 0x40)
		meth |= SC_AC_PRO;
	if (sc_byte & 0x20)
		meth |= SC_AC_AUT | SC_AC_TERM;
	if (sc_byte & 0x10)
		meth |= SC_AC_CHV;

	return sc_file_add_acl_entry(file, ops, meth, sc_byte & 0x0f);
}

static int gemsafe_setacl(sc_card_t *card, sc_file_t *file, const u8 *data,
	int is_df)
{
	int       r;
	u8        cond;
	const u8 *p = data + 1;
	struct sc_context *ctx = card->ctx;

	if (is_df) {
		if (*data & 0x04)	/* CREATE DF */
			cond = *p++;
		else
			cond = 0xff;
		sc_log(ctx, 
			"DF security byte CREATE DF: %02x\n", cond);
		r = gemsafe_sc2acl(file, SC_AC_OP_CREATE, cond);
		if (r < 0)
			return r;
		if (*data & 0x02)	/* CREATE EF */
			cond = *p;
		else
			cond = 0xff;
		sc_log(ctx, 
			"DF security byte CREATE EF: %02x\n", cond);
		/* XXX: opensc doesn't currently separate access conditions for
		 * CREATE EF and CREATE DF, this should be changed */
		r = gemsafe_sc2acl(file, SC_AC_OP_CREATE, cond);
		if (r < 0)
			return r;
	} else {
		/* XXX: ACTIVATE FILE and DEACTIVATE FILE ac are currently not
		 * supported => ignore them */
		if (*data & 0x02)	/* UPDATE BINARY, ERASE BINARY */
			cond = *p++;
		else
			cond = 0xff;
		sc_log(ctx, 
			"EF security byte UPDATE/ERASE BINARY: %02x\n", cond);
		r = gemsafe_sc2acl(file, SC_AC_OP_UPDATE, cond);
		if (r < 0)
			return r;
		r = gemsafe_sc2acl(file, SC_AC_OP_WRITE, cond);
		if (r < 0)
			return r;
		r = gemsafe_sc2acl(file, SC_AC_OP_ERASE, cond);
		if (r < 0)
			return r;
		if (*data & 0x01)	/* READ BINARY */
			cond = *p;
		else
			cond = 0xff;
		sc_log(ctx, 
			"EF security byte READ BINARY: %02x\n", cond);
		r = gemsafe_sc2acl(file, SC_AC_OP_READ, cond);
		if (r < 0)
			return r;
	}

	return SC_SUCCESS;
}

static int gemsafe_process_fci(struct sc_card *card, struct sc_file *file,
	const u8 *buf, size_t len)
{
	int        r;
	size_t     tlen;
	const u8   *tag = NULL, *p = buf;
	const char *type;
	struct sc_context *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	r = iso_ops->process_fci(card, file, buf, len);
	if (r < 0)
		return r;
	sc_log(ctx, 
		"processing GemSAFE V1 specific FCI information\n");


	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &tlen);
	if (!tag) {
		/* no FDB => we have a DF */
		type = "DF";
		file->type = SC_FILE_TYPE_DF;
	} else {
		type = "EF";
		file->type = SC_FILE_TYPE_WORKING_EF;
	}

	sc_log(ctx,  "file type: %s\n", type);

	tag = sc_asn1_find_tag(ctx, p, len, 0x8C, &tlen);
	if (tag) {
		r = gemsafe_setacl(card, file, tag, strcmp(type, "DF") ? 0 : 1);
		if (r < 0) {
			sc_log(ctx,  "unable to set ACL\n");
			return SC_ERROR_INTERNAL;
		}
	} else
		sc_log(ctx,  "error: AM and SC bytes missing\n");

	return SC_SUCCESS;
}

static u8 gemsafe_flags2algref(struct sc_card *card, const struct sc_security_env *env)
{
	u8 ret = 0;

	if (env->operation == SC_SEC_OPERATION_SIGN) {
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)
			ret = GEMSAFEV3_ALG_REF_SHA256;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			ret = (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
			       card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) ?
			      GEMSAFEV3_ALG_REF_FREEFORM :
			      GEMSAFEV1_ALG_REF_FREEFORM;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_ISO9796)
			ret = 0x11;
	} else if (env->operation == SC_SEC_OPERATION_DECIPHER) {
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			ret = (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
			       card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) ?
			      GEMSAFEV3_ALG_REF_FREEFORM :
			      GEMSAFEV1_ALG_REF_FREEFORM;
	}

	return ret;
}

static int gemsafe_restore_security_env(struct sc_card *card, int se_num)
{
	int r;
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0x73, (u8) se_num);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


static int gemsafe_set_security_env(struct sc_card *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	u8 alg_ref;
	struct sc_security_env se_env = *env;
	struct sc_context *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (!(se_env.flags & SC_SEC_ENV_ALG_REF_PRESENT)) {
		/* set the algorithm reference */
		alg_ref = gemsafe_flags2algref(card, &se_env);
		if (alg_ref) {
			se_env.algorithm_ref = alg_ref;
			se_env.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
		}
	}
	if (!(se_env.flags & SC_SEC_ENV_ALG_REF_PRESENT))
		sc_log(ctx,  "unknown algorithm flags '%x'\n", se_env.algorithm_flags);

	se_env.flags &= ~SC_SEC_ENV_FILE_REF_PRESENT;
	return iso_ops->set_security_env(card, &se_env, se_num);
}

static int gemsafe_compute_signature(struct sc_card *card, const u8 * data,
	size_t data_len, u8 * out, size_t outlen)
{
	int r, len;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_context_t *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* the card can sign 36 bytes of free form data */
	if (data_len > 36) {
		sc_log(ctx, 
			 "error: input data too long: %"SC_FORMAT_LEN_SIZE_T"u bytes\n",
			 data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* the Portuguese eID card requires a two-phase exchange */
	/* and so does the Swedish one */
	if(card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
	   card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x90, 0xA0);
	} else {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0xAC);
		apdu.cla |= 0x80;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le      = 256;
	}
	/* we sign a digestInfo object => tag 0x90 */
	sbuf[0] = 0x90;
	sbuf[1] = (u8)data_len;
	memcpy(sbuf + 2, data, data_len);
	apdu.data = sbuf;
	apdu.lc   = data_len + 2;
	apdu.datalen = data_len + 2;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		if(card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID ||
		   card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) {
			/* finalize the exchange */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A, 0x9E, 0x9A);
			apdu.le = 128; /* 1024 bit keys */
			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			if(card->type == SC_CARD_TYPE_GEMSAFEV1_SEEID) {
			  /* cla 0x80 not supported */
			  apdu.cla = 0x00;
			}
			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
			if(apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
		}
		len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int gemsafe_decipher(struct sc_card *card, const u8 * crgram,
	size_t crgram_len, u8 *out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_context_t *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x84);
	apdu.cla |= 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le      = crgram_len;

	apdu.data = crgram;
	apdu.lc   = crgram_len;
	apdu.datalen = crgram_len;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		int len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int gemsafe_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	int prev_cla, r;

	prev_cla = card->cla;
	if(card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID) {
		/* Warning: this depends on iso7816_get_challenge not
		 * changing the value of the card's CLA
		 */
		card->cla = 0x80;
	}
	r = iso_ops->get_challenge(card, rnd, len);
	/* Restore the CLA value if needed */
	if(card->cla != prev_cla)
		card->cla = prev_cla;

	return r;
}

static int gemsafe_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;
	gemsafe_exdata *exdata = (gemsafe_exdata *)card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0 && exdata) {
		r = gp_select_applet(card, exdata->aid, exdata->aid_len);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (!iso_ops)
		iso_ops = iso_drv->ops;
	/* use the standard iso operations as default */
	gemsafe_ops = *iso_drv->ops;
	/* gemsafe specific functions */
	gemsafe_ops.match_card	= gemsafe_match_card;
	gemsafe_ops.init	= gemsafe_init;
	gemsafe_ops.finish	= gemsafe_finish;
	gemsafe_ops.select_file	= gemsafe_select_file;
	gemsafe_ops.restore_security_env = gemsafe_restore_security_env;
	gemsafe_ops.set_security_env     = gemsafe_set_security_env;
	gemsafe_ops.decipher             = gemsafe_decipher;
	gemsafe_ops.compute_signature    = gemsafe_compute_signature;
	gemsafe_ops.get_challenge 		 = gemsafe_get_challenge;
	gemsafe_ops.process_fci	= gemsafe_process_fci;
	gemsafe_ops.pin_cmd		 = iso_ops->pin_cmd;
	gemsafe_ops.card_reader_lock_obtained = gemsafe_card_reader_lock_obtained;

	return &gemsafe_drv;
}

struct sc_card_driver *sc_get_gemsafeV1_driver(void)
{
	return sc_get_driver();
}

