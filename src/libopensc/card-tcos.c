/*
 * card-tcos.c: Support for TCOS 2.0 cards
 *
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

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include <string.h>
#include <ctype.h>
#include <time.h>

static const char *tcos_atrs[] = {
	"3B:BA:13:00:81:31:86:5D:00:64:05:0A:02:01:31:80:90:00:8B", /* SLE44 */
	"3B:BA:14:00:81:31:86:5D:00:64:05:14:02:02:31:80:90:00:91", /* SLE66S */
	"3B:BA:96:00:81:31:86:5D:00:64:05:60:02:03:31:80:90:00:66", /* SLE66P */
	NULL
};

static struct sc_card_operations tcos_ops;
static struct sc_card_driver tcos_drv = {
	"TCOS 2.0 cards",
	"tcos",
	&tcos_ops
};

static const struct sc_card_operations *iso_ops = NULL;


static int tcos_finish(struct sc_card *card)
{
	return 0;
}

static int tcos_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; tcos_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = tcos_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int tcos_init(struct sc_card *card)
{
        unsigned long flags;

	card->name = "TCOS";
	card->drv_data = NULL;
	card->cla = 0x00;

        flags = SC_ALGORITHM_RSA_RAW;
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
        flags |= SC_ALGORITHM_RSA_HASH_NONE;

        _sc_card_add_rsa_alg(card, 512, flags, 0);
        _sc_card_add_rsa_alg(card, 768, flags, 0);
        _sc_card_add_rsa_alg(card, 1024, flags, 0);

	return 0;
}


/* Hmmm, I don't know what to do.  It seems that the ACL design of
   OpenSC should be enhanced to allow for the command based security
   attributes of TCOS.  FIXME: This just allows to create a very basic
   file. */
static int tcos_construct_fci(const struct sc_file *file,
                              u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
        int n;

        /* FIXME: possible buffer overflow */

        *p++ = 0x6F; /* FCI */
        p++;

	/* File size */
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, 16, &p);

        /* File descriptor */
        n = 0;
	buf[n] = file->shareable ? 0x40 : 0;
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		break;
	case SC_FILE_TYPE_DF:
		buf[0] |= 0x38;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	buf[n++] |= file->ef_structure & 7;
        if ( (file->ef_structure & 7) > 1) {
                /* record structured file */
                buf[n++] = 0x41; /* indicate 3rd byte */
                buf[n++] = file->record_length;
        }
	sc_asn1_put_tag(0x82, buf, n, p, 8, &p);

        /* File identifier */
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, 16, &p);

        /* Directory name */
        if (file->type == SC_FILE_TYPE_DF) {
                if (file->namelen) {
                        if (file->namelen > 16 || !file->name)
                                return SC_ERROR_INVALID_ARGUMENTS;
                        sc_asn1_put_tag(0x84, file->name, file->namelen,
                                        p, 16, &p);
                }
                else {
                        /* TCOS needs one, so we use a faked one */
                        snprintf ((char *) buf, sizeof(buf)-1, "foo-%lu",
                                  (unsigned long) time (NULL));
                        sc_asn1_put_tag(0x84, buf, strlen ((char *) buf), p, 16, &p);
                }
        }

        /* File descriptor extension */
        if (file->prop_attr_len && file->prop_attr) {
		n = file->prop_attr_len;
		memcpy(buf, file->prop_attr, n);
        }
        else {
                n = 0;
                buf[n++] = 0x01; /* not invalidated, permanent */
                if (file->type == SC_FILE_TYPE_WORKING_EF) 
                        buf[n++] = 0x00; /* generic data file */
        }
        sc_asn1_put_tag(0x85, buf, n, p, 16, &p);

        /* Security attributes */
	if (file->sec_attr_len && file->sec_attr) {
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		n = file->sec_attr_len;
	}
        else {
                /* no attributes given - fall back to default one */
                memcpy (buf+ 0, "\xa4\x00\x00\x00\xff\xff", 6); /* select */
                memcpy (buf+ 6, "\xb0\x00\x00\x00\xff\xff", 6); /* read bin */
                memcpy (buf+12, "\xd6\x00\x00\x00\xff\xff", 6); /* upd bin */
                memcpy (buf+18, "\x60\x00\x00\x00\xff\xff", 6); /* admin grp*/
                n = 24;
        }
        sc_asn1_put_tag(0x86, buf, n, p, sizeof (buf), &p);

        
        /* fixup length of FCI */
        out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}


static int tcos_create_file(struct sc_card *card, struct sc_file *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;
	r = tcos_construct_fci(file, sbuf, &len);
	SC_TEST_RET(card->ctx, r, "tcos_construct_fci() failed");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
        apdu.cla |= 0x80;  /* this is an proprietary extension */
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}



static int map_operations (int commandbyte )
{
  int op = -1;

  switch ( (commandbyte & 0xfe) )
    {
    case 0xe2: /* append record */   op = SC_AC_OP_UPDATE; break;
    case 0x24: /* change password */ op = SC_AC_OP_UPDATE; break;
    case 0xe0: /* create */          op = SC_AC_OP_CREATE; break;
    case 0xe4: /* delete */          op = SC_AC_OP_DELETE; break;
    case 0xe8: /* exclude sfi */     op = SC_AC_OP_WRITE; break;
    case 0x82: /* external auth */   op = SC_AC_OP_READ; break;
    case 0xe6: /* include sfi */     op = SC_AC_OP_WRITE; break;
    case 0x88: /* internal auth */   op = SC_AC_OP_READ; break;
    case 0x04: /* invalidate */      op = SC_AC_OP_INVALIDATE; break;
    case 0x2a: /* perform sec. op */ op = SC_AC_OP_SELECT; break;
    case 0xb0: /* read binary */     op = SC_AC_OP_READ; break;
    case 0xb2: /* read record */     op = SC_AC_OP_READ; break;
    case 0x44: /* rehabilitate */    op = SC_AC_OP_REHABILITATE; break;
    case 0xa4: /* select */          op = SC_AC_OP_SELECT; break;
    case 0xee: /* set permanent */   op = SC_AC_OP_CREATE; break;
    case 0x2c: /* unblock password */op = SC_AC_OP_WRITE; break;
    case 0xd6: /* update binary */   op = SC_AC_OP_WRITE; break;
    case 0xdc: /* update record */   op = SC_AC_OP_WRITE; break;
    case 0x20: /* verify password */ op = SC_AC_OP_SELECT; break;
    case 0x60: /* admin group */     op = SC_AC_OP_CREATE; break;
    }
  return op;
}




/* Hmmm, I don't know what to do.  It seems that the ACL design of
   OpenSC should be enhanced to allow for the command based security
   attributes of TCOS.  FIXME: This just allows to create a very basic
   file. */
static void parse_sec_attr(struct sc_card *card,
                           struct sc_file *file, const u8 *buf, size_t len)
{
        int op;
        
        /* list directory is not covered by ACLs - so always add an entry */
        sc_file_add_acl_entry (file, SC_AC_OP_LIST_FILES,
                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
        /* FIXME: check for what LOCK is used */
        sc_file_add_acl_entry (file, SC_AC_OP_LOCK,
                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
        for (; len >= 6; len -= 6, buf += 6) {
                /* FIXME: temporary hacks */
                if (!memcmp(buf, "\xa4\x00\x00\x00\xff\xff", 6)) /* select */
                        sc_file_add_acl_entry (file, SC_AC_OP_SELECT,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\xb0\x00\x00\x00\xff\xff", 6)) /*read*/
                        sc_file_add_acl_entry (file, SC_AC_OP_READ,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\xd6\x00\x00\x00\xff\xff", 6)) /*upd*/
                        sc_file_add_acl_entry (file, SC_AC_OP_UPDATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\x60\x00\x00\x00\xff\xff", 6)) {/*adm */
                        sc_file_add_acl_entry (file, SC_AC_OP_WRITE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_CREATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_INVALIDATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_REHABILITATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                }
                else {
                        /* the first byte tells use the command or the
                           command group.  We have to mask bit 0
                           because this one distinguish between AND/OR
                           combination of PINs*/
                        op = map_operations (buf[0]);
                        if (op == -1)
                        {
                                sc_debug (card->ctx,
                                       "Unknown security command byte %02x\n",
                                       buf[0]);
                                continue;
                        }
                        if (!buf[1])
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_NONE,
                                                       SC_AC_KEY_REF_NONE);
                        else
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_CHV, buf[1]);

                        if (!buf[2] && !buf[3])
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_NONE,
                                                       SC_AC_KEY_REF_NONE);
                        else
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_TERM,
                                                       (buf[2]<<8)|buf[3]);
                }
        }
}

/* Arghh. duplicated from iso7816.c */
static void tcos_process_fci(struct sc_context *ctx, struct sc_file *file,
                             const u8 *buf, size_t buflen)
{
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	if (ctx->debug >= 3)
		sc_debug(ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (ctx->debug >= 3)
			sc_debug(ctx, "  file identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (ctx->debug >= 3)
			sc_debug(ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			if (ctx->debug >= 3)
				sc_debug(ctx, "  bytes in file: %d\n", bytes);
			file->size = bytes;
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (ctx->debug >= 3)
				sc_debug(ctx, "  shareable: %s\n",
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
			if (ctx->debug >= 3) {
				sc_debug(ctx, "  type: %s\n", type);
				sc_debug(ctx, "  EF structure: %d\n",
				       byte & 0x07);
			}
		}
	}
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
		if (ctx->debug >= 3)
			sc_debug(ctx, "File name: %s\n", name);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_sec_attr(file, tag, taglen); 
	}
	file->magic = SC_FILE_MAGIC;
}


/* This is a special version of the standard select_file which is
   needed to cope with some starngeness in APDU construction.  It is
   probably better to have this specfic for TCOS, so that support for
   other cards does not break. */
static int hacked_iso7816_select_file(struct sc_card *card,
                                      const struct sc_path *in_path,
                                      struct sc_file **file_out)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	struct sc_file *file = NULL;

	assert(card != NULL && in_path != NULL);
	ctx = card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			if (pathlen == 2) {	/* only 3F00 supplied */
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	default:
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0;		/* first record, return FCI */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 255; /* 256 will be represented as 0 which
                                  conflicts with the apdu sanity check */
	} else {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 255; 
		/* does not work apdu.cse = SC_APDU_CASE_3_SHORT;*/
	}
        if (!apdu.lc) /* never send an empty lc */
          apdu.cse = SC_APDU_CASE_2_SHORT;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, 2, 0);
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, 2, r);

	switch (apdu.resp[0]) {
	case 0x6F:
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		if (apdu.resp[1] <= apdu.resplen)
			tcos_process_fci(card->ctx, file,
                                         apdu.resp+2, apdu.resp[1]);
		*file_out = file;
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	default:
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	return 0;
}



static int tcos_select_file(struct sc_card *card,
			    const struct sc_path *in_path,
			    struct sc_file **file)
{
	int r;
	
 	/*r = iso_ops->select_file(card, in_path, file);*/
 	r = hacked_iso7816_select_file(card, in_path, file);
	if (r)
		return r;

	if (file) {
                parse_sec_attr(card, (*file), (*file)->sec_attr,
                               (*file)->sec_attr_len);
        }

	return 0;
}

static int tcos_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 p1s[2] = { 0x01, 0x02 };
	int r, i, count = 0;

	for (i = 0; i < 2; i++) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, p1s[i], 0);
		apdu.cla = 0x80;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r == SC_ERROR_FILE_NOT_FOUND)
			continue;
		SC_TEST_RET(card->ctx, r, "Card returned error");
		if (apdu.resplen > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(buf, apdu.resp, apdu.resplen);
		buf += apdu.resplen;
		buflen -= apdu.resplen;
		count += apdu.resplen;
	}
	return count;
}



static int tcos_delete_file(struct sc_card *card, const struct sc_path *path)
{
	int r;
	u8 sbuf[2];
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_error(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	sbuf[0] = path->value[0];
	sbuf[1] = path->value[1];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
        apdu.cla |= 0x80;
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

/* Crypto operations */


/* Although the TCOS manual says that the manage security environment
   is compatible with 7816-8.2 we use our own implementation here.
   The problem is that I don't have the ISO specs and Juha's 7816 code
   uses parameters which are not described in the TCOS specs.  [wk] 
*/
static int tcos_set_security_env(struct sc_card *card,
                                 const struct sc_security_env *env,
                                 int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
        if (se_num) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

        if (env->operation == SC_SEC_OPERATION_SIGN) {
                /* There is only a default security environment for
                   signature creation. */
		return 0;
        }

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p1 = 0xC1;
		apdu.p2 = 0xB8;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (se_num > 0) {
		r = sc_lock(card);
		SC_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_perror(card->ctx, r, "APDU transmit failed");
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_perror(card->ctx, r, "Card returned error");
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_unlock(card);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

/* See tcos_set_security_env() for comments.  So we always return
   success */
static int tcos_restore_security_env(struct sc_card *card, int se_num)
{
	return 0;
}


/* Issue the SET PERMANENT command.  With ENABLE_NULLPIN set the
   NullPIN method will be activated, otherwise the permanent operation
   will be done on the active file. */
static int tcos_setperm(struct sc_card *card, int enable_nullpin)
{
	int r;
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xEE, 0x00, 0x00);
        apdu.cla |= 0x80;
	apdu.lc = 0;
	apdu.datalen = 0;
	apdu.data = NULL;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int tcos_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_TCOS_SETPERM:
		return tcos_setperm(card, !!ptr);
	}
	sc_error(card->ctx, "card_ctl command %u not supported\n", cmd);
	return SC_ERROR_NOT_SUPPORTED;
}


/* Driver binding stuff */
static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	tcos_ops = *iso_drv->ops;
	tcos_ops.match_card = tcos_match_card;
	tcos_ops.init = tcos_init;
        tcos_ops.finish = tcos_finish;
	if (iso_ops == NULL)
                iso_ops = iso_drv->ops;
	tcos_ops.create_file = tcos_create_file;
	tcos_ops.set_security_env = tcos_set_security_env;
	tcos_ops.select_file = tcos_select_file;
	tcos_ops.list_files  = tcos_list_files;
        tcos_ops.delete_file = tcos_delete_file;
        tcos_ops.set_security_env	= tcos_set_security_env;
        tcos_ops.restore_security_env	= tcos_restore_security_env;
        tcos_ops.card_ctl    = tcos_card_ctl;
	
        return &tcos_drv;
}

struct sc_card_driver * sc_get_tcos_driver(void)
{
	return sc_get_driver();
}
