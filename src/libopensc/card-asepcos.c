/*
 * Copyright (c) 2007  Athena Smartcard Solutions Inc.
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

#include <ctype.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static const struct sc_card_operations *iso_ops = NULL;

struct sc_card_operations asepcos_ops;
static struct sc_card_driver asepcos_drv = {
	"Athena ASEPCOS",
	"asepcos",
	&asepcos_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table asepcos_atrs[] = {
	{ "3b:d6:18:00:81:b1:80:7d:1f:03:80:51:00:61:10:30:8f", NULL, NULL, SC_CARD_TYPE_ASEPCOS_GENERIC, 0, NULL},
	{ "3b:d6:18:00:81:b1:fe:7d:1f:03:41:53:45:37:35:35:01", NULL, NULL, SC_CARD_TYPE_ASEPCOS_JAVA, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static int asepcos_match_card(sc_card_t *card)
{
	int i = _sc_match_atr(card, asepcos_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int asepcos_select_asepcos_applet(sc_card_t *card)
{
	static const u8 asepcos_aid[] = {0xA0,0x00,0x00,0x01,0x64,0x41,0x53,0x45,0x50,0x43,0x4F,0x53,0x00};
	sc_path_t tpath;
	int       r;

	memset(&tpath, 0, sizeof(sc_path_t));

	tpath.type = SC_PATH_TYPE_DF_NAME;
	tpath.len  = sizeof(asepcos_aid);
	memcpy(tpath.value, asepcos_aid, sizeof(asepcos_aid));

	r = sc_select_file(card, &tpath, NULL);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx,  "unable to select ASEPCOS applet");
		return r;
	}

	return SC_SUCCESS;
}

static int asepcos_init(sc_card_t *card)
{
	unsigned long	flags;

	card->name = "Athena ASEPCOS";
	card->cla  = 0x00;

	/* in case of a Java card try to select the ASEPCOS applet */
	if (card->type == SC_CARD_TYPE_ASEPCOS_JAVA) {
		int r = asepcos_select_asepcos_applet(card);
		if (r != SC_SUCCESS)
			return SC_ERROR_INVALID_CARD;
	}

	/* Set up algorithm info. */
	flags =	SC_ALGORITHM_RSA_RAW
		| SC_ALGORITHM_RSA_HASH_NONE
		| SC_ALGORITHM_ONBOARD_KEY_GEN
		;
	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 1792, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_USE_FCI_AC;

	return SC_SUCCESS;
}

/* tables to map the asepcos access mode bytes to the OpenSC 
 * access mode flags */

typedef struct {
	unsigned int am;
	unsigned int sc;
} amode_entry_t;

static const amode_entry_t df_amode_table[] = {
	{ 0x40,	SC_AC_OP_DELETE_SELF },	/* DELETE self  */
	{ 0x01, SC_AC_OP_DELETE },	/* DELETE child */
	{ 0x10, SC_AC_OP_INVALIDATE },	/* DEACTIVATE FILE */
	{ 0x08, SC_AC_OP_REHABILITATE },/* ACTIVATE FILE   */
	{ 0x04, SC_AC_OP_CREATE },	/* CREATE DF    */
	{ 0x02, SC_AC_OP_CREATE },	/* CREATE EF    */
	{ 0, 0 }
};

static const amode_entry_t wef_amode_table[] = {
	{ 0x04, SC_AC_OP_WRITE },
	{ 0x02, SC_AC_OP_UPDATE },
	{ 0x01, SC_AC_OP_READ },
	{ 0, 0 },
};

static const amode_entry_t ief_amode_table[] = {
	{ 0x90, SC_AC_OP_REHABILITATE },
	/* UPDATE is also used when a new key is generated */
	{ 0x82, SC_AC_OP_UPDATE },
	{ 0, 0 },
};

static int set_sec_attr(sc_file_t *file, unsigned int am, unsigned int ac, 
	unsigned int meth)
{
	const amode_entry_t *table;

        /* CHV with reference '0' is the transport PIN
	 * and is presented as 'AUT' key with reference '0'*/
	if (meth == SC_AC_CHV && ac == 0)
		meth = SC_AC_AUT;

	if (file->type == SC_FILE_TYPE_DF)
		table = df_amode_table;
	else if (file->type == SC_FILE_TYPE_WORKING_EF)
		table = wef_amode_table;
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		table = ief_amode_table;
	else
		return SC_ERROR_INVALID_ARGUMENTS;
	for (; table->am != 0; table++) {
		if (table->am & am)
			sc_file_add_acl_entry(file, table->sc, meth, ac);
	}
	return SC_SUCCESS;
}

/* Convert asepcos security attributes to opensc access conditions.
 */
static int asepcos_parse_sec_attr(sc_card_t *card, sc_file_t *file, const u8 *buf,
	size_t len)
{
	const u8 *p = buf;

	while (len != 0) {
		unsigned int amode, tlen = 3;
		if (len < 5 || p[0] != 0x80 || p[1] != 0x01) {
			sc_log(card->ctx,  "invalid access mode encoding");
			return SC_ERROR_INTERNAL;
		}
		amode = p[2];
		if (p[3] == 0x90 && p[4] == 0x00) {
			int r = set_sec_attr(file, amode, 0, SC_AC_NONE);
			if (r != SC_SUCCESS) 
				return r;
			tlen += 2;
		} else if (p[3] == 0x97 && p[4] == 0x00) {
			int r = set_sec_attr(file, amode, 0, SC_AC_NEVER);
			if (r != SC_SUCCESS) 
				return r;
			tlen += 2;
		} else if (p[3] == 0xA0 && len >= 4U + p[4]) {
			/* TODO: support OR expressions */
			int r = set_sec_attr(file, amode, p[5], SC_AC_CHV);
			if (r != SC_SUCCESS)
				return r;
			tlen += 2 + p[4]; /* FIXME */
		} else if (p[3] == 0xAF && len >= 4U + p[4]) {
			/* TODO: support AND expressions */
			int r = set_sec_attr(file, amode, p[5], SC_AC_CHV);
			if (r != SC_SUCCESS)
				return r;
			tlen += 2 + p[4];	/* FIXME */
		} else {
			sc_log(card->ctx,  "invalid security condition");
			return SC_ERROR_INTERNAL;
		}
		p   += tlen;
		len -= tlen;
	}

	return SC_SUCCESS;
}

/* sets a TLV encoded path as returned from GET DATA in a sc_path_t object
 */
static int asepcos_tlvpath_to_scpath(sc_path_t *out, const u8 *in, size_t in_len)
{
	int    r;
	size_t len = in_len;

	memset(out, 0, sizeof(sc_path_t));

	while (len != 0) {
		if (len < 4)
			return SC_ERROR_INTERNAL;
		if (in[0] != 0x8b || in[1] != 0x02)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		/* append file id to the path */
		r = sc_append_path_id(out, &in[2], 2);
		if (r != SC_SUCCESS)
			return r;
		len -= 4;
		in  += 4;
	}
	out->type = SC_PATH_TYPE_PATH;

	return SC_SUCCESS;
}

/* returns the currently selected DF (if a EF is currently selected
 * it returns the path from the MF to the DF in which the EF is
 * located.
 * @param  card  sc_card_t object to use
 * @param  path  OUT path from the MF to the current DF
 * @return SC_SUCCESS on success and an error value otherwise
 */
static int asepcos_get_current_df_path(sc_card_t *card, sc_path_t *path)
{
	int r;
	sc_apdu_t apdu;
	u8        rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x83); 
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le      = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	return asepcos_tlvpath_to_scpath(path, apdu.resp, apdu.resplen);
}

/* SELECT FILE: call the ISO SELECT FILE implementation and parse 
 * asepcos specific security attributes.
 */
static int asepcos_select_file(sc_card_t *card, const sc_path_t *in_path,
	sc_file_t **file)
{
	int       r;
	sc_path_t npath = *in_path;

	LOG_FUNC_CALLED(card->ctx);

	if (in_path->type == SC_PATH_TYPE_PATH) {
		/* check the current DF to avoid unnecessary re-selection of
		 * the MF (as this might invalidate a security status) */
		sc_path_t tpath;
		memset(&tpath, 0, sizeof tpath);

		r = asepcos_get_current_df_path(card, &tpath);
		/* workaround: as opensc can't handle paths with file id
		 * and application names in it let's ignore the current
		 * DF if the returned path contains a unsupported tag.
		 */
		if (r != SC_ERROR_INVALID_ASN1_OBJECT && r != SC_SUCCESS)
			return r;
		if (r == SC_SUCCESS && sc_compare_path_prefix(&tpath, &npath) != 0) {
			/* remove the currently selected DF from the path */
			if (tpath.len == npath.len) {
				/* we are already in the requested DF */
				if (file == NULL)
					/* no file information requested => 
					 * nothing to do */
					return SC_SUCCESS;
			} else {
				/* shorten path */
				r = sc_path_set(&npath, 0, &in_path->value[tpath.len], 
						npath.len - tpath.len, 0, 0);
				if (r != SC_SUCCESS)
					return r;
				if (npath.len == 2)
					npath.type = SC_PATH_TYPE_FILE_ID;
				else
					npath.type = SC_PATH_TYPE_PATH;
			}
		}
	}

	r = iso_ops->select_file(card, &npath, file);
	/* XXX: this doesn't look right */
	if (file != NULL && *file != NULL) 
		if ((*file)->ef_structure == SC_FILE_EF_UNKNOWN)
			(*file)->ef_structure = SC_FILE_EF_TRANSPARENT;
	if (r == SC_SUCCESS && file != NULL && *file != NULL) {
		r = asepcos_parse_sec_attr(card, *file, (*file)->sec_attr, (*file)->sec_attr_len);
		if (r != SC_SUCCESS) 
			sc_log(card->ctx,  "error parsing security attributes");
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int asepcos_set_security_env(sc_card_t *card,
	const sc_security_env_t *env, int se_num)
{
	return SC_SUCCESS;
}


static int asepcos_akn_to_fileid(sc_card_t *card, sc_cardctl_asepcos_akn2fileid_t *p)
{
	int r;
	u8  sbuf[32], rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	sbuf[0] = p->akn & 0xff;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x28, 0x02, 0x01);
	apdu.cla    |= 0x80;
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le      = 256;
	apdu.lc      = 1;
	apdu.datalen = 1;
	apdu.data    = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.resplen != 4)
		return SC_ERROR_INTERNAL;

	p->fileid = (apdu.resp[1] << 16) | (apdu.resp[2] << 8) | apdu.resp[3];

	return SC_SUCCESS;
}

/* sets the security attribute of a EF/DF
 */
static int asepcos_set_sec_attributes(sc_card_t *card, const u8 *data, size_t len,
	int is_ef)
{
	int r, type = is_ef != 0 ? 0x02 : 0x04;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x8a, type, 0xab);
	apdu.cla    |= 0x80;
	apdu.lc      = len;
	apdu.datalen = len;
	apdu.data    = data;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

/* encodes the opensc file attributes into the card specific format
 */
static int asepcos_set_security_attributes(sc_card_t *card, sc_file_t *file)
{
	size_t i;
	const amode_entry_t *table;
	u8     buf[64], *p;
	int    r = SC_SUCCESS;

	/* first check whether the security attributes in encoded form
	 * are already set. If present use these */
	if (file->sec_attr != NULL && file->sec_attr_len != 0)
		return asepcos_set_sec_attributes(card, file->sec_attr,
				file->sec_attr_len, file->type == SC_FILE_TYPE_DF ? 0:1);
	/* otherwise construct the ACL from the opensc ACLs */
	if (file->type == SC_FILE_TYPE_DF)
		table = df_amode_table;
	else if (file->type == SC_FILE_TYPE_WORKING_EF)
		table = wef_amode_table;
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		table = ief_amode_table;
	else
		return SC_ERROR_INVALID_ARGUMENTS;

	p = buf;
	for (i = 0; table[i].am != 0; i++) {
		const struct sc_acl_entry *ent = sc_file_get_acl_entry(file, table[i].sc);
		if (ent == NULL)
			continue;
		*p++ = 0x80;
		*p++ = 0x01;
		*p++ = table[i].am & 0xff;
		if (ent->method == SC_AC_NONE) {
			*p++ = 0x90;
			*p++ = 0x00;
		} else if (ent->method == SC_AC_NEVER) {
			*p++ = 0x97;
			*p++ = 0x00;
		} else if (ent->method == SC_AC_CHV) {
			sc_cardctl_asepcos_akn2fileid_t st;
			st.akn = ent->key_ref;
			r = asepcos_akn_to_fileid(card, &st);
			if (r != SC_SUCCESS)
				return r;
			*p++ = 0xa0;
			*p++ = 0x05;
			*p++ = 0x89;
			*p++ = 0x03;
			*p++ = (st.fileid >> 16) & 0xff;
			*p++ = (st.fileid >> 8 ) & 0xff;
			*p++ = st.fileid & 0xff;
		} else {
			sc_log(card->ctx,  "unknown auth method: '%d'", ent->method);
			return SC_ERROR_INTERNAL;
		} 
	}

	if (p != buf)
		r = asepcos_set_sec_attributes(card, buf, p-buf, file->type == SC_FILE_TYPE_DF ? 0:1);
	return r;
}

static int asepcos_decipher(sc_card_t *card, const u8 * crgram, size_t crgram_len,
	u8 * out, size_t outlen)
{
	int       r;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	/* call RSA ENCRYPT DECRYPT for the decipher operation */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x14, 0x01, 0x00);
	apdu.cla    |= 0x80;
	apdu.resp    = out;
	apdu.resplen = outlen;
	/* if less than 256 bytes are expected than set Le to 0x00
	 * to tell the card the we want everything available (note: we
	 * always have Le <= crgram_len) */
	apdu.le      = (outlen >= 256 && crgram_len < 256) ? 256 : outlen;
	
	apdu.data    = crgram;
	apdu.lc      = crgram_len;
	apdu.datalen = crgram_len;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	return apdu.resplen;
}

/* compute the signature. Currently the RSA ENCRYPT DECRYPT command
 * is used here (TODO: use the key attributes to determine method
 * to use for signature generation). 
 */
static int asepcos_compute_signature(sc_card_t *card, const u8 *data, size_t datalen,
			 u8 *out, size_t outlen)
{
	int r = SC_SUCCESS, atype;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	if (datalen >= 256)
		atype = SC_APDU_CASE_4_EXT;
	else
		atype = SC_APDU_CASE_4_SHORT;
	sc_format_apdu(card, &apdu, atype, 0x14, 0x01, 0x00);
	apdu.cla    |= 0x80;
	apdu.lc      = datalen;
	apdu.datalen = datalen;
	apdu.data    = data;
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le      = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
		sc_log(card->ctx,  "error creating signature");
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	if (apdu.resplen > outlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(out, apdu.resp, apdu.resplen);

	return apdu.resplen;
}

/* activates the EF/DF specified in the file id.
 */
static int asepcos_activate_file(sc_card_t *card, int fileid, int is_ef)
{
	int r, type = is_ef != 0 ? 2 : 1;
	sc_apdu_t apdu;
	u8 sbuf[2];

	sbuf[0] = (fileid >> 8) & 0xff;
	sbuf[1] = fileid & 0xff;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x44, type, 0x00);
	apdu.lc      = 2;
	apdu.datalen = 2;
	apdu.data    = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
} 

/* CREATE FILE: creates wEF, iEF and DFs. Note: although the ISO
 * command is used for wEF and iEF so format of the data send to
 * the card is asepcos specific. 
 * @param  card  the sc_card_t object to use
 * @param  file  sc_file_t object describing the file to create 
 * @return SC_SUCCESS on success and an error code otherwise.
 */
static int asepcos_create_file(sc_card_t *card, sc_file_t *file)
{
	if (file->type == SC_FILE_TYPE_DF) {
		int r, type;
		sc_apdu_t apdu;
		u8  sbuf[SC_MAX_APDU_BUFFER_SIZE], *p = &sbuf[0];

		*p++ = (file->id >> 8) & 0xff;
		*p++ = file->id & 0xff;
		if (file->size > 0xffff) {
			*p++ = (file->size >> 24) & 0xff;
			*p++ = (file->size >> 16) & 0xff;
			*p++ = (file->size >> 8 ) & 0xff;
			*p++ = file->size & 0xff;
			type = 1;
		} else {
			*p++ = (file->size >> 8) & 0xff;
			*p++ = file->size & 0xff;
			type = 0;
		}
		if (file->namelen != 0 && file->namelen <= 16) {
			memcpy(p, file->name, file->namelen);
			p += file->namelen;
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xe0, 0x38, type);
		apdu.cla    |= 0x80;
		apdu.lc      = p - sbuf;
		apdu.datalen = p - sbuf;
		apdu.data    = sbuf;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return sc_check_sw(card, apdu.sw1, apdu.sw2); 

		r = sc_select_file(card, &file->path, NULL);
		if (r != SC_SUCCESS)
			return r;
		/* set security attributes */
		r = asepcos_set_security_attributes(card, file);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "unable to set security attributes");
			return r;
		}
		return SC_SUCCESS;
	} else if (file->type == SC_FILE_TYPE_WORKING_EF) {
		int r;
		sc_apdu_t apdu;
		u8  descr_byte = file->ef_structure & 7;
		u8  sbuf[SC_MAX_APDU_BUFFER_SIZE], *p = &sbuf[0];

		*p++ = 0x85;
		p++;
		/* file id  */
		*p++ = (file->id >> 8) & 0xff;
		*p++ = file->id & 0xff;
		/* record size */
		if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
			*p++ = 0x00;
			*p++ = 0x00;
		} else {
			*p++ = (file->record_length >> 8) & 0xff;
			*p++ = file->record_length & 0xff;
		}
		/* number of records or file size */
		if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
			*p++ = (file->size >> 8) & 0xff;
			*p++ = file->size & 0xff;
		} else {
			*p++ = (file->record_count >> 8) & 0xff;
			*p++ = file->record_count & 0xff;
		}
		/* set the length of the inner TLV object */
		sbuf[1] = p - sbuf - 2;		/* FIXME */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xe0, descr_byte, 0x00);
		apdu.lc      = p - sbuf;
		apdu.datalen = p - sbuf;
		apdu.data    = sbuf;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return sc_check_sw(card, apdu.sw1, apdu.sw2);

		/* set security attributes */
		r = asepcos_set_security_attributes(card, file);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "unable to set security attributes");
			return r;
		}
		return asepcos_activate_file(card, file->id, 1);
	} else if (file->type == SC_FILE_TYPE_INTERNAL_EF) {
		/* for internal EF we 'misuse' the prop_attr field of the
		 * sc_file_t object to store the data send to the card in
		 * the CREATE EF call. 
		 */
		int r, atype = SC_APDU_CASE_3_SHORT;
		sc_apdu_t apdu;

		if (file->prop_attr_len > 255)
			atype = SC_APDU_CASE_3_EXT;

		sc_format_apdu(card, &apdu, atype, 0xe0, 0x08, 0x00);
		apdu.lc      = file->prop_attr_len;
		apdu.datalen = file->prop_attr_len;
		apdu.data    = file->prop_attr;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return sc_check_sw(card, apdu.sw1, apdu.sw2);
		/* set security attributes */
		r = asepcos_set_security_attributes(card, file);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "unable to set security attributes");
			return r;
		}
		return asepcos_activate_file(card, file->id, 1);
	} else
		return SC_ERROR_INVALID_ARGUMENTS;
}

/* list files: the function first calls GET DATA to get the current
 * working DF. It then re-selects the DF to get proprietary FCI which
 * contain the FID of the first child DF EF.
 * The FID of the other EFs/DFs within the selected DF are then
 * obtained by selecting the know FIDs to get next child EF/DF.
 * @param  card  the sc_card_t object to use
 * @param  buff  the output buffer for the list of FIDs
 * @param  blen  the length of the buffer
 * @return the number of FIDs read on success and an error value otherwise.
 */
static int asepcos_list_files(sc_card_t *card, u8 *buf, size_t blen)
{
	int       r, rv = 0, dfFID, efFID;
	sc_path_t bpath, tpath;
	sc_file_t *tfile = NULL;

	/* 1. get currently selected DF */
	r = asepcos_get_current_df_path(card, &bpath);
	if (r != SC_SUCCESS)
		return r;
	/* 2. re-select DF to get the FID of the child EFs/DFs */
	r = sc_select_file(card, &bpath, &tfile);
	if (r != SC_SUCCESS)
		return r;
	if (tfile->prop_attr_len != 6 || tfile->prop_attr == NULL) {
		sc_file_free(tfile);
		sc_log(card->ctx,  "unable to parse proprietary FCI attributes");
		return SC_ERROR_INTERNAL;
	}
	dfFID = (tfile->prop_attr[2] << 8) | tfile->prop_attr[3];
	efFID = (tfile->prop_attr[4] << 8) | tfile->prop_attr[5];
	sc_file_free(tfile);
	/* 3. select every child DF to get the FID of the next child DF */
	while (dfFID != 0) {
		/* put DF FID on the list */
		if (blen < 2)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*buf++ = (dfFID >> 8) & 0xff;
		*buf++ = dfFID & 0xff;
		rv   += 2;
		blen -= 2;
		/* select DF to get next DF FID */
		tpath = bpath;
		r = sc_append_file_id(&tpath, dfFID);
		if (r != SC_SUCCESS)
			return r;
		r = sc_select_file(card, &tpath, &tfile);
		if (r != SC_SUCCESS)
			return r;
		if (tfile->prop_attr_len != 6 || tfile->prop_attr == NULL)
			return SC_ERROR_INTERNAL;
		dfFID = (tfile->prop_attr[0] << 8) | tfile->prop_attr[1];
		sc_file_free(tfile);
	}
	/* 4. select every child EF ... */
	while (efFID != 0) {
		/* put DF FID on the list */
		if (blen < 2)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*buf++ = (efFID >> 8) & 0xff;
		*buf++ = efFID & 0xff;
		rv   += 2;
		blen -= 2;
		/* select EF to get next EF FID */
		tpath = bpath;
		r = sc_append_file_id(&tpath, efFID);
		if (r != SC_SUCCESS)
			return r;
		r = sc_select_file(card, &tpath, &tfile);
		if (r != SC_SUCCESS)
			return r;
		if (tfile->prop_attr_len < 2 || tfile->prop_attr == NULL)
			return SC_ERROR_INTERNAL;
		efFID = (tfile->prop_attr[0] << 8) | tfile->prop_attr[1];
		sc_file_free(tfile);
	}

	return rv;
}

static int asepcos_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int       r, ftype, atype;
	sc_apdu_t apdu;
	u8        buf[SC_MAX_APDU_BUFFER_SIZE];

	/* use GET DATA to determine whether it is a DF or EF */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x84);
	apdu.le      = 256;
	apdu.resplen = sizeof(buf);
	apdu.resp    = buf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		/* looks like a EF */
		atype = SC_APDU_CASE_3_SHORT;
		ftype = 0x02;
		buf[0] = path->value[path->len-2]; 
		buf[1] = path->value[path->len-1];
	} else {
		/* presumably a DF */
		atype = SC_APDU_CASE_1;
		ftype = 0x00;
	}
	
	sc_format_apdu(card, &apdu, atype, 0xe4, ftype, 0x00);
	if (atype == SC_APDU_CASE_3_SHORT) {
		apdu.lc      = 2;
		apdu.datalen = 2;
		apdu.data    = buf;
	}
	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

/* returns the default transport key (note: this should be put in the 
 * pkcs15 profile file).
 */
static int asepcos_get_default_key(sc_card_t *card,
	struct sc_cardctl_default_key *data)
{
	static const u8 asepcos_def_key[] = {0x41,0x53,0x45,0x43,0x41,0x52,0x44,0x2b};
	if (data->method != SC_AC_CHV && data->method != SC_AC_AUT)
		return SC_ERROR_NO_DEFAULT_KEY;
	if (data->key_data == NULL || data->len < sizeof(asepcos_def_key))
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(data->key_data, asepcos_def_key, sizeof(asepcos_def_key));
	data->len = sizeof(asepcos_def_key);
	return SC_SUCCESS;
}

static int asepcos_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	sc_apdu_t apdu;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x14);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le   = 256;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r,  "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	if (apdu.resplen != 8) {
		sc_log(card->ctx,  "unexpected response to GET DATA serial number\n");
		return SC_ERROR_INTERNAL;
	}
	/* cache serial number */
	memcpy(card->serialnr.value, rbuf, 8);
	card->serialnr.len = 8;
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

static int asepcos_change_key(sc_card_t *card, sc_cardctl_asepcos_change_key_t *p)
{
	int       r, atype;
	sc_apdu_t apdu;

	if (p->datalen > 255)
		atype = SC_APDU_CASE_3_EXT;
	else
		atype = SC_APDU_CASE_3_SHORT;

	sc_format_apdu(card, &apdu, atype, 0x24, 0x01, 0x80);
	apdu.lc      = p->datalen;
	apdu.datalen = p->datalen;
	apdu.data    = p->data;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int asepcos_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return asepcos_get_default_key(card, (struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return asepcos_get_serialnr(card, (sc_serial_number_t *)ptr);
	case SC_CARDCTL_ASEPCOS_CHANGE_KEY:
		return asepcos_change_key(card, (sc_cardctl_asepcos_change_key_t*)ptr);
	case SC_CARDCTL_ASEPCOS_AKN2FILEID:
		return asepcos_akn_to_fileid(card, (sc_cardctl_asepcos_akn2fileid_t*)ptr);
	case SC_CARDCTL_ASEPCOS_SET_SATTR:
		return asepcos_set_security_attributes(card, (sc_file_t*)ptr);
	case SC_CARDCTL_ASEPCOS_ACTIVATE_FILE:
		return asepcos_activate_file(card, ((sc_cardctl_asepcos_activate_file_t*)ptr)->fileid,
		                           ((sc_cardctl_asepcos_activate_file_t *)ptr)->is_ef);
	}
	return SC_ERROR_NOT_SUPPORTED;
}

/* build the different APDUs for the PIN handling commands
 */
static int asepcos_build_pin_apdu(sc_card_t *card, sc_apdu_t *apdu,
	struct sc_pin_cmd_data *data, u8 *buf, size_t buf_len,
	unsigned int cmd, int is_puk)
{
	int r, fileid;
	u8  *p = buf;
	sc_cardctl_asepcos_akn2fileid_t st;

	switch (cmd) {
	case SC_PIN_CMD_VERIFY:
		st.akn = data->pin_reference;
		r = asepcos_akn_to_fileid(card, &st);
		if (r != SC_SUCCESS)
			return r;
		fileid = st.fileid;
		/* the fileid of the puk is the fileid of the pin + 1 */
		if (is_puk != 0)
			fileid++;
		sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x02, 0x80);
		*p++ = (fileid >> 24) & 0xff;
		*p++ = (fileid >> 16) & 0xff;
		*p++ = (fileid >> 8 ) & 0xff;
		*p++ = fileid & 0xff;
		memcpy(p, data->pin1.data, data->pin1.len);
		p += data->pin1.len;
		apdu->lc       = p - buf;
		apdu->datalen  = p - buf;
		apdu->data     = buf;
		break;
	case SC_PIN_CMD_CHANGE:
		/* build the CHANGE KEY apdu. Note: the PIN file is implicitly
		 * selected by its SFID */
		*p++ = 0x81;
		*p++ = data->pin2.len & 0xff;
		memcpy(p, data->pin2.data, data->pin2.len);
		p   += data->pin2.len;
		st.akn = data->pin_reference;
		r = asepcos_akn_to_fileid(card, &st);
		if (r != SC_SUCCESS)
			return r;
		fileid = 0x80 | (st.fileid & 0x1f);
		sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, fileid);
		apdu->lc       = p - buf;
		apdu->datalen  = p - buf;
		apdu->data     = buf;
		break;
	case SC_PIN_CMD_UNBLOCK:
		/* build the UNBLOCK KEY apdu. The PIN file is implicitly 
		 * selected by its SFID. The new PIN is provided in the
		 * data field of the UNBLOCK KEY command. */
		*p++ = 0x81;
		*p++ = data->pin2.len & 0xff;
		memcpy(p, data->pin2.data, data->pin2.len);
		p   += data->pin2.len;
		st.akn = data->pin_reference;
		r = asepcos_akn_to_fileid(card, &st);
		if (r != SC_SUCCESS)
			return r;
		fileid = 0x80 | (st.fileid & 0x1f);
		sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x2C, 0x02, fileid);
		apdu->lc       = p - buf;
		apdu->datalen  = p - buf;
		apdu->data     = buf;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	return SC_SUCCESS;
}

/* generic function to handle the different PIN operations, i.e verify
 * change and unblock.
 */
static int asepcos_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *pdata,
	int *tries_left)
{
	sc_apdu_t apdu;
	int r = SC_SUCCESS;
	u8  sbuf[SC_MAX_APDU_BUFFER_SIZE];

	if (tries_left)
		*tries_left = -1;

	/* only PIN verification is supported at the moment  */

	/* check PIN length */
	if (pdata->pin1.len < 4 || pdata->pin1.len > 16) {
		sc_log(card->ctx,  "invalid PIN1 length");
		return SC_ERROR_INVALID_PIN_LENGTH; 
	}

	switch (pdata->cmd) {
	case SC_PIN_CMD_VERIFY:
		if (pdata->pin_type != SC_AC_CHV && pdata->pin_type != SC_AC_AUT)
			return SC_ERROR_INVALID_ARGUMENTS;
		/* 'AUT' key is the transport PIN and should have reference '0' */
		if (pdata->pin_type == SC_AC_AUT && pdata->pin_reference)
			return SC_ERROR_INVALID_ARGUMENTS;
		/* build verify APDU and send it to the card */
		r = asepcos_build_pin_apdu(card, &apdu, pdata, sbuf, sizeof(sbuf), SC_PIN_CMD_VERIFY, 0);
		if (r != SC_SUCCESS)
			break;
		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS)
			sc_log(card->ctx,  "APDU transmit failed");
		break;
	case SC_PIN_CMD_CHANGE:
		if (pdata->pin_type != SC_AC_CHV)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (pdata->pin2.len < 4 || pdata->pin2.len > 16) {
			sc_log(card->ctx,  "invalid PIN2 length");
			return SC_ERROR_INVALID_PIN_LENGTH; 
		}
		/* 1. step: verify the old pin */
		r = asepcos_build_pin_apdu(card, &apdu, pdata, sbuf, sizeof(sbuf), SC_PIN_CMD_VERIFY, 0);
		if (r != SC_SUCCESS)
			break;
		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "APDU transmit failed");
			break;
		}
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
			/* unable to verify the old PIN */
			break;
		}
		/* 2, step: use CHANGE KEY to update the PIN */
		r = asepcos_build_pin_apdu(card, &apdu, pdata, sbuf, sizeof(sbuf), SC_PIN_CMD_CHANGE, 0);
		if (r != SC_SUCCESS)
			break;
		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS)
			sc_log(card->ctx,  "APDU transmit failed");
		break;
	case SC_PIN_CMD_UNBLOCK:
		if (pdata->pin_type != SC_AC_CHV)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (pdata->pin2.len < 4 || pdata->pin2.len > 16) {
			sc_log(card->ctx,  "invalid PIN2 length");
			return SC_ERROR_INVALID_PIN_LENGTH; 
		}
		/* 1. step: verify the puk */
		r = asepcos_build_pin_apdu(card, &apdu, pdata, sbuf, sizeof(sbuf), SC_PIN_CMD_VERIFY, 1);
		if (r != SC_SUCCESS)
			break;
		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "APDU transmit failed");
			break;
		}
		/* 2, step: unblock and change the pin */
		r = asepcos_build_pin_apdu(card, &apdu, pdata, sbuf, sizeof(sbuf), SC_PIN_CMD_UNBLOCK, 0);
		if (r != SC_SUCCESS)
			break;
		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx,  "APDU transmit failed");
			break;
		}
		break;
	default:
		sc_log(card->ctx,  "error: unknown cmd type");
		return SC_ERROR_INTERNAL;
	}
	/* Clear the buffer - it may contain pins */
	sc_mem_clear(sbuf, sizeof(sbuf));
	/* check for remaining tries if verification failed */
	if (r == SC_SUCCESS) {
		if (apdu.sw1 == 0x63) {
			if ((apdu.sw2 & 0xF0) == 0xC0 && tries_left != NULL)
				*tries_left = apdu.sw2 & 0x0F;
			r = SC_ERROR_PIN_CODE_INCORRECT;
			return r;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	return r;
}

static int asepcos_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0 && card->type == SC_CARD_TYPE_ASEPCOS_JAVA) {
		/* in case of a Java card try to select the ASEPCOS applet */
		r = asepcos_select_asepcos_applet(card);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_driver * sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	asepcos_ops = *iso_ops;
	asepcos_ops.match_card        = asepcos_match_card;
	asepcos_ops.init              = asepcos_init;
	asepcos_ops.select_file       = asepcos_select_file;
	asepcos_ops.set_security_env  = asepcos_set_security_env;
	asepcos_ops.decipher          = asepcos_decipher;
	asepcos_ops.compute_signature = asepcos_compute_signature;
	asepcos_ops.create_file       = asepcos_create_file;
	asepcos_ops.delete_file       = asepcos_delete_file;
	asepcos_ops.list_files        = asepcos_list_files;
	asepcos_ops.card_ctl          = asepcos_card_ctl;
	asepcos_ops.pin_cmd           = asepcos_pin_cmd;
	asepcos_ops.card_reader_lock_obtained = asepcos_card_reader_lock_obtained;

	return &asepcos_drv;
}

struct sc_card_driver * sc_get_asepcos_driver(void)
{
	return sc_get_driver();
}
