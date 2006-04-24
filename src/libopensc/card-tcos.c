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
#include <stdlib.h>

static struct sc_atr_table tcos_atrs[] = {
	/* SLE44 */
	{ "3B:BA:13:00:81:31:86:5D:00:64:05:0A:02:01:31:80:90:00:8B", NULL, NULL, SC_CARD_TYPE_TCOS_GENERIC, 0, NULL },
	/* SLE66S */
	{ "3B:BA:14:00:81:31:86:5D:00:64:05:14:02:02:31:80:90:00:91", NULL, NULL, SC_CARD_TYPE_TCOS_GENERIC, 0, NULL },
	/* SLE66CX320P */
	{ "3B:BA:96:00:81:31:86:5D:00:64:05:60:02:03:31:80:90:00:66", NULL, NULL, SC_CARD_TYPE_TCOS_GENERIC, 0, NULL },
	/* SLE66CX322P */
        { "3B:BA:96:00:81:31:86:5D:00:64:05:7B:02:03:31:80:90:00:7D", NULL, NULL, SC_CARD_TYPE_TCOS_GENERIC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations tcos_ops;
static struct sc_card_driver tcos_drv = {
	"TCOS 2.0",
	"tcos",
	&tcos_ops,
	NULL, 0, NULL
};

static const struct sc_card_operations *iso_ops = NULL;

typedef struct tcos_data_st {
	unsigned int pad_flags;
	unsigned int sign_with_def_env;
} tcos_data;

static int tcos_finish(sc_card_t *card)
{
	free(card->drv_data);
	return 0;
}

static int tcos_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, tcos_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int tcos_init(sc_card_t *card)
{
        unsigned long flags;

	tcos_data *data = (tcos_data *) malloc(sizeof(tcos_data));
	if (!data)
		return SC_ERROR_OUT_OF_MEMORY;

	card->name = "TCOS";
	card->drv_data = (void *)data;
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
static int tcos_construct_fci(const sc_file_t *file,
                              u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
        size_t n;

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


static int tcos_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

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



static unsigned int map_operations (int commandbyte )
{
  unsigned int op = (unsigned int)-1;

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
static void parse_sec_attr(sc_card_t *card,
                           sc_file_t *file, const u8 *buf, size_t len)
{
        unsigned int op;
        
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
                        if (op == (unsigned int)-1)
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
static void tcos_process_fci(sc_context_t *ctx, sc_file_t *file,
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
static int hacked_iso7816_select_file(sc_card_t *card,
                                      const sc_path_t *in_path,
                                      sc_file_t **file_out)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	sc_file_t *file = NULL;

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



static int tcos_select_file(sc_card_t *card,
			    const sc_path_t *in_path,
			    sc_file_t **file)
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

static int tcos_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
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



static int tcos_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	u8 sbuf[2];
	sc_apdu_t apdu;

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


/* TCOS has two kind of RSA-keys: signature-keys and encryption-keys
   signature-keys: can be used for sign-operations only and can be used
     only within the default security environment. hence must be
     stored as local key 0, a SetSecEnv-cmd must not be used (if you
     do - even with default parameters - it will fail with 6A88)
   encryption-keys: can be used for both sign- and decipher-operations,
     can be used within any security environment, a SetSecEnv-cmd
     must be used (even if you want to use the default security environment
     you must a SetSecEnv-cmd with default parameters)
   Unfortunately we cannot find out wether the referenced key is a
   signature-key or encryption-key when this routine is called. Therefore
   we have a problem if the key-reference is 0x80. If the referenced key
   was a signature-key a SetSecEnv must not be used, if the key was an
   encryption-key it must be used.
   Therefore we suppress error-messages in this case, try a SetSecEnv-cmd
   with default parameters and watch out for 6A88-responses [pk_opensc@web.de]
*/
static int tcos_set_security_env(sc_card_t *card,
                                 const sc_security_env_t *env,
                                 int se_num)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE], *p;
	int r, sign_with_def_env=0;

	assert(card != NULL && env != NULL);
	ctx = card->ctx;

        if (se_num) SC_FUNC_RETURN(ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if(ctx->debug >= 3) sc_debug(ctx, "Security Environment Ref=%d:%02X\n", env->key_ref_len, *env->key_ref);
	if(env->operation == SC_SEC_OPERATION_SIGN &&
	   (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || (env->key_ref_len==1 && *env->key_ref==0x80))
	){
		if (ctx->debug >= 3) sc_debug(ctx, "Sign-Operation with Default Security Environment\n");
		sign_with_def_env=1;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0xC1;
		apdu.p2 = 0xB8;
		/* save padding flags and default secEnv indictor */
		((tcos_data *)card->drv_data)->pad_flags = env->algorithm_flags;
		((tcos_data *)card->drv_data)->sign_with_def_env = sign_with_def_env;
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
		*p++ = (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC) ? 0x83 : 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;

	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_perror(ctx, r, "APDU transmit failed");
			return r;
		}
		if (sign_with_def_env && apdu.sw1==0x6A && apdu.sw2==0x88) return 0;
		((tcos_data *)card->drv_data)->sign_with_def_env = sign_with_def_env = 0;

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_perror(ctx, r, "Card returned error");
			return r;
		}
	}
	return 0;
}


/* See tcos_set_security_env() for comments.  So we always return
   success */
static int tcos_restore_security_env(sc_card_t *card, int se_num)
{
	return 0;
}

/**
 * TCOS compute_signature command. As TCOS can compute signatures
 * with the default security environment only, signatures with other
 * security environments are computed by encrypting the pkcs1-padded data
 */
static int tcos_compute_signature(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
	int r;
	size_t i;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && data != NULL && out != NULL);

	if (datalen > 255) SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);

	if(((tcos_data *)card->drv_data)->sign_with_def_env){
		if(datalen>48){
			sc_error(card->ctx, "Data to be signed is too long (TCOS supports max. 48 bytes)\n");
			SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
		memcpy(sbuf, data, datalen);
	} else {
		unsigned int keylen=128; /* FIXME: use correct key-size */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x84);
		for(i = 0; i < sizeof(sbuf); ++i)
			sbuf[i]=0xff;
		sbuf[0]=0x00; sbuf[1]=0x01; sbuf[keylen-datalen-1]=0x00;
		memcpy(sbuf+keylen-datalen, data, datalen);
		datalen=keylen;
	}
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	apdu.sensitive = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 4, len);
	}
	SC_FUNC_RETURN(card->ctx, 4, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/**
 * TCOS decipher command (same as iso7816_decipher besides setting
 * the padding byte).
 */
static int tcos_decipher(sc_card_t *card,
			    const u8 * crgram, size_t crgram_len,
			    u8 * out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	tcos_data *xdata;
	u8 pad_byte;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && crgram != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = crgram_len;
	apdu.sensitive = 1;
	
	xdata = (tcos_data *)card->drv_data;
	if (xdata->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
		pad_byte = 0x81;	/* pkcs1 padding */
	else
		pad_byte = 0x02;	/* no padding */
	/* Note: the 'ISO' padding (0x80, 0x00, 0x00 ...) supported
	 * by TCOS cards is ignored here as OpenSC doesn't support it
	 * -- Nils 
	 */
		
	sbuf[0] = pad_byte;
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 2, len);
	}
	SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


/* Issue the SET PERMANENT command.  With ENABLE_NULLPIN set the
   NullPIN method will be activated, otherwise the permanent operation
   will be done on the active file. */
static int tcos_setperm(sc_card_t *card, int enable_nullpin)
{
	int r;
	sc_apdu_t apdu;

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

/* read the card serial number from the EF_gdo system file */
static int tcos_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int       r;
	u8        buf[64];
	size_t    len;
	sc_path_t tpath;
	sc_file_t *tfile = NULL;

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}
	/* read EF_gdo */
	sc_format_path("3F002F02", &tpath);
	r = sc_select_file(card, &tpath, &tfile);
	if (r < 0)
		return r;
	len = tfile->size;
	sc_file_free(tfile);
	if (len > sizeof(buf) || len < 12)
		return SC_ERROR_INTERNAL;
	r = sc_read_binary(card, 0, buf, len, 0);
	if (r < 0)
		return r;
	if (buf[0] != 0x5a || buf[1] > len - 2)
		return SC_ERROR_INTERNAL;
	card->serialnr.len = buf[1];	
	memcpy(card->serialnr.value, buf+2, buf[1]);

	memcpy(serial, &card->serialnr, sizeof(*serial));

	return SC_SUCCESS;
}

static int tcos_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_TCOS_SETPERM:
		return tcos_setperm(card, !!ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return tcos_get_serialnr(card, (sc_serial_number_t *)ptr);
	}
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
	tcos_ops.compute_signature	= tcos_compute_signature;
	tcos_ops.decipher    = tcos_decipher;
	tcos_ops.restore_security_env	= tcos_restore_security_env;
	tcos_ops.card_ctl    = tcos_card_ctl;
	
	return &tcos_drv;
}

struct sc_card_driver * sc_get_tcos_driver(void)
{
	return sc_get_driver();
}
