/*
 * card-gpk: Driver for GPK 4000 cards
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
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

#include "sc-internal.h"
#include "sc-log.h"
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#ifdef HAVE_OPENSSL

/* GPK4000 variants */
enum {
	GPK4000_su256,
	GPK4000_s,
	GPK4000_sp,
	GPK4000_sdo,
};

#define GPK_SEL_MF	0x00
#define GPK_SEL_DF	0x01
#define GPK_SEL_EF	0x02
#define GPK_SEL_AID	0x04
#define GPK_FID_MF	0x3F00

/*
 * GPK4000 private data
 */
struct gpk_private_data {
	int		variant;

	/* access control bits of file most recently selected */
	u_int16_t	ac[3];

	/* is non-zero if we should use secure messaging */
	u_int8_t	key_set   : 1;
	u_int8_t	key_local : 1,
			key_sfi   : 5;
	u_int8_t	key[16];
};
#define OPSDATA(card)	((struct gpk_private_data *) ((card)->ops_data))

/*
 * ATRs of GPK4000 cards courtesy of libscez
 */
static struct atrinfo {
	unsigned char	atr[SC_MAX_ATR_SIZE];
	unsigned int	atr_len;
	int		variant;
} atrlist[] = {
  { "\x3B\x27\x00\x80\x65\xA2\x04\x01\x01\x37", 10, GPK4000_s },
  { "\x3B\x27\x00\x80\x65\xA2\x05\x01\x01\x37", 10, GPK4000_sp },
  { "\x3B\x27\x00\x80\x65\xA2\x0C\x01\x01\x37", 10, GPK4000_su256 },
  { "\x3B\xA7\x00\x40\x14\x80\x65\xA2\x14\x01\x01\x37", 12, GPK4000_sdo },

  { "", 0, -1 }
};

/*
 * Driver and card ops structures
 */
static struct sc_card_operations	gpk_ops;
static const struct sc_card_driver gpk_drv = {
	NULL,
	"Gemplus GPK 4000 driver",
	"gpk",
	&gpk_ops
};


/*
 * Identify the card variant based on the ATR
 */
static struct atrinfo *
gpk_identify(struct sc_card *card)
{
	struct atrinfo	*ai;

	for (ai = atrlist; ai->atr_len; ai++) {
		if (card->atr_len >= ai->atr_len
		 && !memcmp(card->atr, ai->atr, ai->atr_len))
			return ai;
	}
	return NULL;
}

/*
 * return 1 iff this driver can handle the card
 */
static int
gpk_match(struct sc_card *card)
{
	return gpk_identify(card)? 1 : 0;
}

/*
 * Initialize the card struct
 */
static int
gpk_init(struct sc_card *card)
{
	struct gpk_private_data *priv;
	struct atrinfo	*ai;

	if (!(ai = gpk_identify(card)))
		return SC_ERROR_INVALID_CARD;
	card->ops_data = priv = malloc(sizeof(*priv));
	if (card->ops_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(priv, 0, sizeof(*priv));
	priv->variant = ai->variant;
	card->cla = 0;

	return 0;
}

/*
 * Card is being closed; discard any private data etc
 */
static int
gpk_finish(struct sc_card *card)
{
	if (card->ops_data)
		free(card->ops_data);
	card->ops_data = NULL;
	return 0;
}

/*
 * Error code handling for the GPK4000.
 * sc_sw_to_errorcode doesn't seem to handle all of the
 * status words the GPK is capable of returning
 */
static int
gpk_sw_to_errorcode(struct sc_card *card, u_int8_t sw1, u_int8_t sw2)
{
	u_int16_t	sw = (sw1 << 8) | sw2;

	if ((sw & 0xFFF0) == 0x63C0) {
		error(card->ctx, "wrong PIN, %u tries left", sw&0xf);
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	switch (sw) {
	case 0x6400:
		error(card->ctx, "wrong crypto context");
		return SC_ERROR_OBJECT_NOT_VALID; /* XXX ??? */
	case 0x6581:
		error(card->ctx, "out of space on card or file");
		return SC_ERROR_OUT_OF_MEMORY;
	case 0x6981:
		return SC_ERROR_FILE_NOT_FOUND;
	case 0x6A80:
	case 0x6b00:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	return sc_sw_to_errorcode(card, sw1, sw2);
}

/*
 * Select a DF/EF
 */
static int
match_path(struct sc_card *card, u_int16_t **pathptr, size_t *pathlen,
		int need_info)
{
	u_int16_t	*curptr, *ptr;
	size_t		curlen, len;
	size_t		i;

	curptr = (u_int16_t *) card->cache.current_path.value;
	curlen = card->cache.current_path.len;
	ptr    = *pathptr;
	len    = *pathlen;

	if (curlen < 1 || len < 1)
		return 0;

	/* Skip the MF if present */
	if (ptr[0] != GPK_FID_MF) {
		curptr++;
		curlen--;
	}

	if (len < curlen)
		return 0;

	for (i = 0; i < len; i++) {
		if (ptr[i] != curptr[i])
			return 0;
	}

	/* Exact match? */
	if (len == curlen && need_info)
		return 0;

	*pathptr = ptr + i;
	*pathlen = len - i;
	return 1;
}

static inline unsigned int
ac_to_acl(u_int16_t ac)
{
	unsigned int	npins, pin;
	unsigned int	res = 0;

	npins = (ac >> 14) & 3;
	if (npins == 3)
		return SC_AC_NEVER;
	pin = ac & 0xFF;
	while (npins--) {
		switch (pin & 7) {
		case 0:	res |= SC_AC_CHV1; break;
		case 1:	res |= SC_AC_CHV2; break;
		default:return SC_AC_NEVER;
		}
		pin >>= 4;
	}

	/* Check whether secure messaging key is specified */
	if (ac & 0x1F00)
		res |= SC_AC_PRO;

	return res;
}

/*
 * Convert ACLs requested by the application to access condition
 * bits supported by the GPK. Since these do not map 1:1 there's
 * some fuzz involved.
 */
static inline void
acl_to_ac(unsigned int acl, u_int8_t *ac)
{
	ac[0] = ac[1] = 0;

	if (acl == SC_AC_NEVER) {
		ac[0] = 0xC0;
		return;
	}

	/* XXX should we set the "local" flag for PINs or not?
	 * OpenSC does not provide for a "lock file" operation
	 * that lets us freeze the ac bits after setting up the file.
	 */
	if (acl & SC_AC_CHV2) {
		ac[0] += 0x40;
		ac[1] |= 1;
	}
	if (acl & SC_AC_CHV1) {
		ac[0] += 0x40;
		ac[1] <<= 4;
		ac[1] |= 0;
	}

	/* XXX should we set the "local" flag on key files or not?
	 * OpenSC does not provide for a "lock file" operation
	 * that lets us freeze the ac bits after setting up the file.
	 */
	if (acl & SC_AC_PRO) {
		ac[0] |= 0x01;
	}
}

static int
gpk_parse_fileinfo(struct sc_card *card,
		const u_int8_t *buf, size_t buflen,
		struct sc_file *file)
{
	struct gpk_private_data *priv = OPSDATA(card);
	const u_int8_t	*sp, *end, *next;
	int		i;

	memset(file, 0, sizeof(*file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		file->acl[i] = SC_AC_UNKNOWN;

	end = buf + buflen;
	for (sp = buf; sp + 2 < end; sp = next) {
		next = sp + 2 + sp[1];
		if (next > end)
			break;
		if (sp[0] == 0x84) {
			/* ignore if name is longer than what it should be */
			if (sp[1] > sizeof(file->name))
				continue;
			memset(file->name, 0, sizeof(file->name));
			memcpy(file->name, sp+2, sp[1]);
		} else
		if (sp[0] == 0x85) {
			unsigned int	ac1, ac2, ac3;

			file->id = (sp[4] << 8) | sp[5];
			file->size = (sp[8] << 8) | sp[9];
			file->record_length = sp[7];

			/* Map ACLs */
			priv->ac[0] = (sp[10] << 8) | sp[11];
			priv->ac[1] = (sp[12] << 8) | sp[13];
			priv->ac[2] = (sp[14] << 8) | sp[15]; /* EF only */
			ac1 = ac_to_acl(priv->ac[0]);
			ac2 = ac_to_acl(priv->ac[1]);
			ac3 = ac_to_acl(priv->ac[2]);

			/* Examine file type */
			switch (sp[6] & 7) {
			case 0x01: case 0x02: case 0x03: case 0x04:
			case 0x05: case 0x06: case 0x07:
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = sp[6] & 7;
				file->acl[SC_AC_OP_READ] = ac3;
				file->acl[SC_AC_OP_WRITE] = ac3;
				file->acl[SC_AC_OP_UPDATE] = ac1;
				break;
			case 0x00: /* 0x38 is DF */
				file->type = SC_FILE_TYPE_DF;
				file->acl[SC_AC_OP_SELECT] = SC_AC_NONE;
				file->acl[SC_AC_OP_LOCK] = ac1;
				/* Icky: the GPK uses different ACLs
				 * for creating data files and
				 * 'sensitive' i.e. key files */
				file->acl[SC_AC_OP_CREATE] = ac2;
				file->acl[SC_AC_OP_DELETE] = SC_AC_NEVER;
				file->acl[SC_AC_OP_REHABILITATE] = SC_AC_NEVER;
				file->acl[SC_AC_OP_INVALIDATE] = SC_AC_NEVER;
				file->acl[SC_AC_OP_LIST_FILES] = SC_AC_NEVER;
				break;
			}
		}
	}

	if (file->record_length)
		file->record_count = file->size / file->record_length;
	file->magic = SC_FILE_MAGIC;

	return 0;
}

static int
gpk_select(struct sc_card *card, u_int8_t kind,
		const u_int8_t *buf, size_t buflen,
		struct sc_file *file)
{
	struct gpk_private_data *priv = OPSDATA(card);
	struct sc_apdu	apdu;
	u_int8_t	resbuf[SC_MAX_APDU_BUFFER_SIZE];
	int		r;

	/* If we're about to select a DF, invalidate secure messaging keys */
	if (kind == GPK_SEL_MF || kind == GPK_SEL_DF) {
		memset(priv->key, 0, sizeof(priv->key));
		priv->key_set = 0;
	}

	/* do the apdu thing */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, kind, 0);
	apdu.data = buf;
	apdu.datalen = buflen;
	apdu.lc = apdu.datalen;
	apdu.resp = resbuf;
	apdu.resplen = file? sizeof(resbuf) : 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = gpk_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	/* Nothing we can say about it... invalidate
	 * path cache */
	if (kind == GPK_SEL_AID) {
		card->cache.current_path.len = 0;
	}

	if (file == NULL)
		return 0;

	return gpk_parse_fileinfo(card, apdu.resp, apdu.resplen, file);
}

static int
gpk_select_id(struct sc_card *card, u_int8_t kind, u_int16_t fid,
		struct sc_file *file)
{
	struct sc_path	*cp = &card->cache.current_path;
	u_int8_t	fbuf[2];
	int		r;

	fbuf[0] = fid >> 8;
	fbuf[1] = fid & 0xff;
	r = gpk_select(card, kind, fbuf, 2, file);

	/* Fix up the path cache */
	if (r == 0) {
		u_int16_t	*path = (u_int16_t *) cp->value;

		if (fid == GPK_FID_MF) {
			path[0] = fid;
			cp->len = 1;
		} else
		if (cp->len + 1 <= SC_MAX_PATH_SIZE / 2) {
			path[cp->len++] = fid;
		} else {
			cp->len = 0;
		}
	} else {
		cp->len = 0;
	}
	return r;
}

static int
gpk_select_file(struct sc_card *card, const struct sc_path *path,
		struct sc_file *file)
{
	u_int16_t	pathtmp[SC_MAX_PATH_SIZE/2];
	u_int16_t	*pathptr;
	size_t		pathlen, n;
	int		locked = 0, r = 0, use_relative = 0;
	u_int8_t	leaf_type;

	SC_FUNC_CALLED(card->ctx, 3);

	/* Handle the AID case first */
	if (path->type == SC_PATH_TYPE_DF_NAME) {
		if (path->len > 16)
			return SC_ERROR_INVALID_ARGUMENTS;
		r = gpk_select(card, GPK_SEL_AID,
					path->value, path->len, file);
		goto done;
	}

	/* Now we know we're dealing with 16bit FIDs, either as
	 * an absolute path name (SC_PATH_TYPE_PATH) or a relative
	 * FID (SC_PATH_TYPE_FILE_ID)
	 *
	 * The API should really tell us whether this is a DF or EF
	 * we're selecting. All we can do is read tea leaves...
	 */
	leaf_type = GPK_SEL_EF;

try_again:
	if ((path->len & 1) || path->len > sizeof(pathtmp))
		return SC_ERROR_INVALID_ARGUMENTS;
	pathptr = pathtmp;
	for (n = 0; n < path->len; n += 2)
		pathptr[n>>1] = (path->value[n] << 8)|path->value[n+1];
	pathlen = path->len >> 1;

	/* See whether we can skip an initial portion of the
	 * (absolute) path */
	if (path->type == SC_PATH_TYPE_PATH) {
		use_relative = match_path(card, &pathptr, &pathlen, file != 0);
		if (pathlen == 0)
			goto done;
	} else {
		/* SC_PATH_TYPE_FILEID */
		if (pathlen > 1)
			return SC_ERROR_INVALID_ARGUMENTS;
		use_relative = 1;
	}

	if (pathlen == 1 && pathptr[0] == GPK_FID_MF) {
		/* Select just the MF */
		leaf_type = GPK_SEL_MF;
	} else {
		if (!locked++) {
			r = sc_lock(card);
			SC_TEST_RET(card->ctx, r, "sc_lock() failed");
		}

		/* Do we need to select the MF first? */
		if (!use_relative) {
			r = gpk_select_id(card, GPK_SEL_MF, GPK_FID_MF, NULL);
			if (r)
				sc_unlock(card);
			SC_TEST_RET(card->ctx, r, "Unable to select MF");

			/* Consume the MF FID if it's there */
			if (pathptr[0] == GPK_FID_MF) {
				pathptr++;
				pathlen--;
			}
			if (pathlen == 0)
				goto done;
		}

		/* Next comes a DF, if at all.
		 * This loop can deal with nesting levels > 1 even
		 * though the GPK4000 doesn't support it. */
		while (pathlen > 1) {
			r = gpk_select_id(card, GPK_SEL_DF, pathptr[0], NULL);
			if (r)
				sc_unlock(card);
			SC_TEST_RET(card->ctx, r, "Unable to select DF");
			pathptr++;
			pathlen--;
		}
	}

	/* Remaining component will be a DF or EF. How do we find out?
	 * All we can do is try */
	r = gpk_select_id(card, leaf_type, pathptr[0], file);
	if (r) {
		/* Did we guess EF, and were wrong? If so, invalidate
		 * path cache and try again; this time aiming for a DF */
		if (leaf_type == GPK_SEL_EF) {
			card->cache.current_path.len = 0;
			leaf_type = GPK_SEL_DF;
			goto try_again;
		}
	}

done:
	if (locked)
		sc_unlock(card);
	return r;
}

/*
 * Secure messaging
 */
static int
gpk_compute_crycks(struct sc_card *card, struct sc_apdu *apdu,
			u_int8_t *crycks1)
{
	struct gpk_private_data *priv = OPSDATA(card);
	des_key_schedule k1, k2;
	u_int8_t	in[8], out[8], block[64];
	unsigned int	len = 0, i, j;

	/* Set the key schedule */
	des_set_key_unchecked((des_cblock *) priv->key, k1);
	des_set_key_unchecked((des_cblock *) (priv->key+8), k2);

	/* Fill block with 0x00 and then with the data. */
	memset(block, 0x00, sizeof(block));
	block[len++] = apdu->cla;
	block[len++] = apdu->ins;
	block[len++] = apdu->p1;
	block[len++] = apdu->p2;
	block[len++] = apdu->lc + 3;
	if ((i = apdu->datalen) + len > sizeof(block))
		i = sizeof(block) - len;
	memcpy(block+len, apdu->data, i);
	len += i;

	/* Set IV */
	memset(in, 0x00, 8);

	for (j = 0; j < len; ) {
		for (i = 0; i < 8; i++, j++)
			in[i] ^= block[j];
		des_ecb3_encrypt((des_cblock *)in,
				 (des_cblock *)out,
				 k1, k2, k1, DES_ENCRYPT);
		memcpy(in, out, 8);
	}

	memcpy((u_int8_t *) (apdu->data + apdu->datalen), out + 5, 3);
	apdu->datalen += 3;
	apdu->lc += 3;
	apdu->le = 3;
	if (crycks1)
		memcpy(crycks1, out, 3);
	memset(k1, 0, sizeof(k1));
	memset(k2, 0, sizeof(k2));
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(block, 0, sizeof(block));
	return 0;
}

/*
 * Create a file or directory.
 * This is a bit tricky because we abuse the ef_structure
 * field to transport file types that are non-standard
 * (the GPK4000 has lots of bizarre file types).
 */
static int
gpk_create_file(struct sc_card *card, struct sc_file *file)
{
	struct gpk_private_data *priv = OPSDATA(card);
	struct sc_apdu	apdu;
	u_int8_t	data[28+3], crycks[3], resp[3];
	size_t		datalen, namelen;
	int		r;

	/* Prepare APDU */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x80;	/* assume no secure messaging */
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = 0xE0;
	apdu.p2  = 0x00;

	/* clear data */
	memset(data, 0, sizeof(data));
	datalen = 12;

	/* FID */
	data[0] = file->id >> 8;
	data[1] = file->id & 0xFF;

	/* encode ACLs */
	if (file->type == SC_FILE_TYPE_DF) {
		/* The GPK4000 has separate AC bits for
		 * creating sensitive files and creating
		 * data files. Since OpenSC has just the notion
		 * of "file" we use the same ACL for both AC words
		 */
		apdu.p1 = 0x01; /* create DF */
		data[2] = 0x38;
		acl_to_ac(file->acl[SC_AC_OP_CREATE], data + 6);
		acl_to_ac(file->acl[SC_AC_OP_CREATE], data + 8);
		if ((namelen = file->namelen) != 0) {
			if (namelen > 16)
				return SC_ERROR_INVALID_ARGUMENTS;
			memcpy(data+datalen, file->name, namelen);
			data[5] = namelen;
			datalen += namelen;
		}
	} else {
		apdu.p1 = 0x02; /* create EF */
		data[2] = file->ef_structure;
		data[3] = file->record_length;
		data[4] = file->size >> 8;
		data[5] = file->size & 0xff;
		acl_to_ac(file->acl[SC_AC_OP_UPDATE], data + 6);
		acl_to_ac(file->acl[SC_AC_OP_WRITE],  data + 8);
		acl_to_ac(file->acl[SC_AC_OP_READ],   data + 10);
	}

	apdu.data = data;
	apdu.datalen = datalen;
	apdu.lc = datalen;

	if (priv->key_set) {
		apdu.cla = 0x84;
		apdu.cse = SC_APDU_CASE_4_SHORT;
		r = gpk_compute_crycks(card, &apdu, crycks);
		if (r)
			return r;
		apdu.resp = resp;
		apdu.resplen = sizeof(resp); /* XXX? */
	}

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = gpk_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (priv->key_set) {
		/* verify CRYCKS response? */
		if (apdu.resplen != 3
		 || memcmp(resp, crycks, 3)) {
			printf("XXX Secure messaging: bad resp\n");
		}
	}

	return r;
}

/*
 * Set the secure messaging key following a Select FileKey
 */
static int
gpk_set_filekey(const u_int8_t *key, const u_int8_t *challenge,
		const u_int8_t *r_rn, u_int8_t *kats)
{
	des_key_schedule	k1, k2;
	des_cblock		out;
	int			r = 0;

	des_set_key_unchecked((des_cblock *) key, k1);
	des_set_key_unchecked((des_cblock *) (key+8), k2);

	des_ecb3_encrypt((des_cblock *)(r_rn+4), (des_cblock *) kats,
			k1, k2, k1, DES_ENCRYPT);
	des_ecb3_encrypt((des_cblock *)(r_rn+4), (des_cblock *) (kats+8),
			k2, k1, k2, DES_ENCRYPT);

	/* Verify Cryptogram presented by the card terminal
	 * XXX: what is the appropriate error code to return
	 * here? INVALID_ARGS doesn't seem quite right
	 */
	des_set_key_unchecked((des_cblock *) kats, k1);
	des_set_key_unchecked((des_cblock *) (kats+8), k2);

	des_ecb3_encrypt((des_cblock *) challenge, &out,
			k1, k2, k1, DES_ENCRYPT );
	if (memcmp(r_rn, out+4, 4) != 0)
		r = SC_ERROR_INVALID_ARGUMENTS;

	memset(k1, 0, sizeof(k1));
	memset(k2, 0, sizeof(k2));
	memset(out, 0, sizeof(out));
	return r;
}

/*
 * Verify a key presented by the user for secure messaging
 */
static int
gpk_select_key(struct sc_card *card, int ref, const u8 *buf, size_t buflen)
{
	struct gpk_private_data *priv = OPSDATA(card);
	struct sc_apdu	apdu;
	u_int8_t	random[8], resp[258];
	unsigned int	n, sfi, key_sfi = 0;
	int		r;

	if (buflen != 16)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* The opensc API doesn't tell us what key it wants to
	 * select, and why. We need to look at the ACs of
	 * the most recently selected file and guess
	 */
	key_sfi = 0;
	for (n = 0; n < 3; n++) {
		sfi = (priv->ac[n] >> 8) & 0x3F;
		if (sfi & 0xF) {
			if (key_sfi && key_sfi != sfi) {
				/* Hm, the file has ACLs with two
				 * different keys. I'm unable to guess
				 * which one I should use, so I throw
				 * up my hands in disgust.
				 */
				/* XXX fix errror code? */
				return SC_ERROR_INVALID_ARGUMENTS;
			}
			key_sfi = sfi;
		}
	}

	/* If no key required, assume transport key :-/ */
	if (key_sfi == 0)
		key_sfi = 0x01;

	/* XXX now do the SelFk */
	RAND_pseudo_bytes(random, sizeof(random));
	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x80;
	apdu.cse = SC_APDU_CASE_4_SHORT;
	apdu.ins = 0x28;
	apdu.p1  = ref << 1;
	apdu.p2  = key_sfi;
	apdu.data = random;
	apdu.datalen = sizeof(random);
	apdu.lc = apdu.datalen;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = gpk_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (apdu.resplen != 12) {
		r = SC_ERROR_UNKNOWN_REPLY;
	} else
	if ((r = gpk_set_filekey(buf, random, resp, priv->key)) == 0) {
		priv->key_set = 1;
		priv->key_local = (key_sfi & 0x20)? 1 : 0;
		priv->key_sfi = key_sfi & 0x1f;
	}

	memset(resp, 0, sizeof(resp));
	return r;
}

/*
 * Verify key (for external auth/secure messaging) or PIN
 * presented by the user
 */
static int
gpk_verify(struct sc_card *card, unsigned int type, int ref,
	const u8 *buf, size_t buflen, int *tries_left)
{
	if (tries_left)
		*tries_left = -1;
	switch (type) {
	case SC_AC_PRO:
		return gpk_select_key(card, ref, buf, buflen);
	}
	return SC_ERROR_INVALID_ARGUMENTS;
}

/*
 * Initialize the driver struct
 */
static const struct sc_card_driver *
sc_get_driver()
{
	if (gpk_ops.match_card == NULL) {
		const struct sc_card_driver *iso_drv;
			
		iso_drv = sc_get_iso7816_driver();
		gpk_ops = *iso_drv->ops;

		gpk_ops.match_card	= gpk_match;
		gpk_ops.init		= gpk_init;
		gpk_ops.finish		= gpk_finish;
		gpk_ops.select_file	= gpk_select_file;
		/* The GPK4000 doesn't have a read directory command. */
		//gpk_ops.list_files	= gpk_list_files;
		gpk_ops.verify		= gpk_verify;
		gpk_ops.create_file	= gpk_create_file;
	}
	return &gpk_drv;
}

const struct sc_card_driver *
sc_get_gpk_driver()
{
	return sc_get_driver();
}

#endif /* ifdef OPENSSL */
