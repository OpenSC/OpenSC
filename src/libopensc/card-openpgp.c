/*
 * card-openpgp.c: Support for OpenPGP card
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
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

/*
 * Specifications:
 * http://www.g10code.de/docs/openpgp-card-1.0.pdf (obsolete)
 * http://www.g10code.de/docs/openpgp-card-1.1.pdf
 * http://www.g10code.de/docs/openpgp-card-2.0.pdf
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "errors.h"

static struct sc_atr_table pgp_atrs[] = {
	{ "3b:fa:13:00:ff:81:31:80:45:00:31:c1:73:c0:01:00:00:90:00:b1", NULL, "OpenPGP card v1.0/1.1", SC_CARD_TYPE_OPENPGP_V1, 0, NULL },
	{ "3b:da:18:ff:81:b1:fe:75:1f:03:00:31:c5:73:c0:01:40:00:90:00:0c", NULL, "CryptoStick v1.2 (OpenPGP v2.0)", SC_CARD_TYPE_OPENPGP_V2, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations pgp_ops;
static struct sc_card_driver pgp_drv = {
	"OpenPGP card",
	"openpgp",
	&pgp_ops,
	NULL, 0, NULL
};

/*
 * The OpenPGP card doesn't have a file system, instead everything
 * is stored in data objects that are accessed through GET/PUT.
 *
 * However, much inside OpenSC's pkcs15 implementation is based on
 * the assumption that we have a file system. So we fake one here.
 *
 * Selecting the MF causes us to select the OpenPGP AID.
 *
 * Everything else is mapped to "file" IDs.
 */

enum _type {		/* DO type */
	SIMPLE      = SC_FILE_TYPE_WORKING_EF,
	CONSTRUCTED = SC_FILE_TYPE_DF
};

enum _version {		/* 2-byte BCD-alike encoded version number */
	OPENPGP_CARD_1_0 = 0x0100,
	OPENPGP_CARD_1_1 = 0x0101,
	OPENPGP_CARD_2_0 = 0x0200
};

enum _access {		/* access flags for the respective DO/file */
	READ_NEVER   = 0x0010,
	READ_PIN1    = 0x0011,
	READ_PIN2    = 0x0012,
	READ_PIN3    = 0x0014,
	READ_ALWAYS  = 0x0018,
	READ_MASK    = 0x00FF,
	WRITE_NEVER  = 0x1000,
	WRITE_PIN1   = 0x1100,
	WRITE_PIN2   = 0x1200,
	WRITE_PIN3   = 0x1400,
	WRITE_ALWAYS = 0x1800,
	WRITE_MASK   = 0x1F00
};

struct blob {
	struct blob *	next;	/* pointer to next sibling */
	struct blob *	parent;	/* pointer to parent */
	struct do_info *info;

	sc_file_t *	file;
	unsigned int	id;
	int		status;

	unsigned char *	data;
	unsigned int	len;
	struct blob *	files;	/* pointer to 1st child */
};

struct do_info {
	unsigned int	id;		/* ID of the DO in question */

	enum _type	type;		/* constructed DO or not */
	enum _access	access;		/* R/W acces levels for the DO */

	/* function to get the DO from the card:
	 * only != NULL is DO if readable and not only a part of a constructed DO */
	int		(*get_fn)(sc_card_t *, unsigned int, u8 *, size_t);
	/* function to write the DO to the card:
	 * only != NULL if DO is writeable under some conditions */
	int		(*put_fn)(sc_card_t *, unsigned int, const u8 *, size_t);
};

static int		pgp_get_card_features(sc_card_t *card);
static int		pgp_finish(sc_card_t *card);
static void		pgp_iterate_blobs(struct blob *, int, void (*func)());

static int		pgp_get_blob(sc_card_t *card, struct blob *blob,
				 unsigned int id, struct blob **ret);
static struct blob *	pgp_new_blob(sc_card_t *, struct blob *, unsigned int, sc_file_t *);
static void		pgp_free_blob(struct blob *);
static int		pgp_get_pubkey(sc_card_t *, unsigned int,
				u8 *, size_t);
static int		pgp_get_pubkey_pem(sc_card_t *, unsigned int,
				u8 *, size_t);

static struct do_info		pgp1_objects[] = {	/* OpenPGP card spec 1.1 */
	{ 0x004f, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x005b, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x005e, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0065, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x006e, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0073, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x007a, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0081, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0082, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0093, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c0, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c1, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c2, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c3, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c4, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c5, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c6, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c7, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c8, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c9, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ca, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cb, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cc, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cd, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ce, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cf, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d0, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e0, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e1, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00e2, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN1   | WRITE_PIN1,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0xa400, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xa401, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0xb600, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xb601, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0xb800, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xb801, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0, 0, 0, NULL, NULL },
};

static struct do_info		pgp2_objects[] = {	/* OpenPGP card spec 2.0 */
	{ 0x004d, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x004f, SIMPLE,      READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x005b, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x005e, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0065, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x006e, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0073, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x007a, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x0081, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0082, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x0093, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c0, SIMPLE,      READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x00c1, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c2, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c3, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c4, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x00c5, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c6, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c7, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c8, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00c9, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ca, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cb, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cc, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cd, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00ce, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00cf, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d0, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d1, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d2, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00d3, SIMPLE,      READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x00f4, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN1   | WRITE_PIN1,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f48, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x5f52, SIMPLE,      READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	{ 0x7f21, CONSTRUCTED, READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f48, CONSTRUCTED, READ_NEVER  | WRITE_NEVER, NULL,               NULL        },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0xa400, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xa401, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0xb600, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xb601, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0xb800, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL        },
	{ 0xb801, SIMPLE,      READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey_pem, NULL        },
	{ 0, 0, 0, NULL, NULL },
};

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))
struct pgp_priv_data {
	struct blob *		mf;
	struct blob *		current;	/* currently selected file */

	enum _version		bcd_version;
	struct do_info		*pgp_objects;

	sc_security_env_t	sec_env;
};


/* ABI: check if card's ATR matches one of driver's */
static int
pgp_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, pgp_atrs, &card->type);
	if (i >= 0) {
		card->name = pgp_atrs[i].name;
		return 1;
	}
	return 0;
}


/* ABI: initialize driver */
static int
pgp_init(sc_card_t *card)
{
        struct pgp_priv_data *priv;
	sc_path_t	aid;
	sc_file_t	*file = NULL;
	struct do_info	*info;
	int		r;
	struct blob 	*child = NULL;

	priv = calloc (1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;

	card->cla = 0x00;

	/* set pointer to correct list of card objects */
	priv->pgp_objects = (card->type == SC_CARD_TYPE_OPENPGP_V2)
				? pgp2_objects : pgp1_objects;

	/* set detailed card version */
	priv->bcd_version = (card->type == SC_CARD_TYPE_OPENPGP_V2)
				? OPENPGP_CARD_2_0 : OPENPGP_CARD_1_1;

	/* select application "OpenPGP" */
	sc_format_path("D276:0001:2401", &aid);
	aid.type = SC_PATH_TYPE_DF_NAME;
	if ((r = iso_ops->select_file(card, &aid, &file)) < 0) {
		pgp_finish(card);
		return r;
	}

	/* read information from AID */
	if (file && file->namelen == 16) {
		/* OpenPGP card spec 1.1 & 2.0, section 4.2.1 & 4.1.2.1 */
		priv->bcd_version = bebytes2ushort(file->name + 6);
		/* kludge: get card's serial number from manufacturer ID + serial number */
		memcpy(card->serialnr.value, file->name + 8, 6);
		card->serialnr.len = 6;
	}

	/* change file path to MF for re-use in MF */
	sc_format_path("3f00", &file->path);

	/* set up the root of our fake file tree */
	priv->mf = pgp_new_blob(card, NULL, 0x3f00, file);
	if (!priv->mf) {
		pgp_finish(card);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	/* select MF */
	priv->current = priv->mf;

	/* Populate MF - add matching blobs listed in the pgp_objects table. */
	for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
		if (((info->access & READ_MASK) == READ_ALWAYS) &&
		    (info->get_fn != NULL)) {
			child = pgp_new_blob(card, priv->mf, info->id, sc_file_new());

			/* catch out of memory condition */
			if (child == NULL) {
				pgp_finish(card);
				return SC_ERROR_OUT_OF_MEMORY;
			}
		}
	}

	/* get card_features from ATR & DOs */
	pgp_get_card_features(card);

	return SC_SUCCESS;
}


/* internal: get features of the card: capabilitis, ... */
static int
pgp_get_card_features(sc_card_t *card)
{
	struct pgp_priv_data *priv = DRVDATA (card);
	unsigned char *hist_bytes = card->atr.value;
	size_t atr_len = card->atr.len;
	size_t i = 0;
	struct blob *blob, *blob6e, *blob73;

	/* get SC_CARD_CAP_APDU_EXT capability */
	while ((i < atr_len) && (hist_bytes[i] != 0x73))
			i++;
	if ((hist_bytes[i] == 0x73) && (atr_len > i+3)) {
		/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
		if (hist_bytes[i+3] & 0x40)
			card->caps |= SC_CARD_CAP_APDU_EXT;
	}
	else if (priv->bcd_version >= OPENPGP_CARD_2_0) {
		/* get card capabilities from "historical bytes" DO */
		if ((pgp_get_blob(card, priv->mf, 0x5f52, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->data[0] == 0x00)) {
			while ((i < blob->len) && (blob->data[i] != 0x73))
				i++;
			/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
			if ((blob->data[i] == 0x73) && (blob->len > i+3) &&
			    (blob->data[i+3] & 0x40))
				card->caps |= SC_CARD_CAP_APDU_EXT;
		}
	}

	if ((pgp_get_blob(card, priv->mf, 0x006e, &blob6e) >= 0) &&
	    (pgp_get_blob(card, blob6e, 0x0073, &blob73) >= 0)) {

		/* get "extended capabilities" DO */
		if ((pgp_get_blob(card, blob73, 0x00c0, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->len > 0)) {
			/* bit 0x40 if first byte means "support for get challenge" */
			if (blob->data[0] & 0x40)
				card->caps |= SC_CARD_CAP_RNG;

			if ((priv->bcd_version >= OPENPGP_CARD_2_0) && (blob->len >= 10)) {
				/* max. send/receive sizes are at bytes 7-8 resp. 9-10 */
				card->max_send_size = bebytes2ushort(blob->data + 6);
				card->max_recv_size = bebytes2ushort(blob->data + 8);
			}
		}

		/* get max. PIN length from "CHV status bytes" DO */
		if ((pgp_get_blob(card, blob73, 0x00c4, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->len > 1)) {
			/* 2nd byte in "CHV status bytes" DO means "max. PIN length" */
			card->max_pin_len = blob->data[1];
		}

		/* get supported algorithms & key lengths from "algorithm attributes" DOs */
		for (i = 0x00c1; i <= 0x00c3; i++) {
			unsigned long flags;

			/* Is this correct? */
			/* OpenPGP card spec 1.1 & 2.0, section 2.1 */
			flags = SC_ALGORITHM_RSA_RAW;
			/* OpenPGP card spec 1.1 & 2.0, section 7.2.9 & 7.2.10 */
			flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
			flags |= SC_ALGORITHM_RSA_HASH_NONE;

			if ((pgp_get_blob(card, blob73, i, &blob) >= 0) &&
			    (blob->data != NULL) && (blob->len >= 4)) {
				if (blob->data[0] == 0x01) {	/* Algorithm ID [RFC4880]: RSA */
					unsigned int keylen = bebytes2ushort(blob->data + 1);

					_sc_card_add_rsa_alg(card, keylen, flags, 0);
				}
			}
		}
	}

	return SC_SUCCESS;
}


/* ABI: terminate driver */
static int
pgp_finish(sc_card_t *card)
{
	if (card != NULL) {
		struct pgp_priv_data *priv = DRVDATA (card);

		if (priv != NULL) {
			/* delete fake file hierarchy */
			pgp_iterate_blobs(priv->mf, 99, pgp_free_blob);

			/* delete private data */
			free(priv);
		}
		card->drv_data = NULL;
	}
	return SC_SUCCESS;
}


/* internal: fill a blob's data */
static int
pgp_set_blob(struct blob *blob, const u8 *data, size_t len)
{
	if (blob->data)
		free(blob->data);
	blob->data = NULL;
	blob->len    = 0;
	blob->status = 0;

	if (len > 0) {
		void *tmp = malloc(len);

		if (tmp == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		blob->data = tmp;
		blob->len  = len;
		memcpy(blob->data, data, len);
	}

	if (blob->file)
		blob->file->size = len;

	return SC_SUCCESS;
}


/* internal: append a blob to the list of children of a given parent blob */
static struct blob *
pgp_new_blob(sc_card_t *card, struct blob *parent, unsigned int file_id,
		sc_file_t *file)
{
	struct blob *blob = NULL;

	if (file == NULL)
		return NULL;

	if ((blob = calloc(1, sizeof(struct blob))) != NULL) {
		struct pgp_priv_data *priv = DRVDATA (card);
		struct do_info *info;

		blob->file = file;

		blob->file->type         = SC_FILE_TYPE_WORKING_EF; /* default */
		blob->file->ef_structure = SC_FILE_EF_TRANSPARENT;
		blob->file->id           = file_id;

		blob->id     = file_id;
		blob->parent = parent;

		if (parent != NULL) {
			struct blob **p;

			/* set file's path = parent's path + file's id */
			blob->file->path = parent->file->path;
			sc_append_file_id(&blob->file->path, file_id);

			/* append blob to list of parent's children */
			for (p = &parent->files; *p != NULL; p = &(*p)->next)
				;
			*p = blob;
		}
		else {
			u8 id_str[2];

			/* no parent: set file's path = file's id */
			sc_format_path(ushort2bebytes(id_str, file_id), &blob->file->path);
		}

		/* find matching DO info: set file type depending on it */
		for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
			if (info->id == file_id) {
				blob->info = info;
				blob->file->type = blob->info->type;
				break;
			}
		}
	}

	return blob;
}


/* internal: free a blob including its content */
static void
pgp_free_blob(struct blob *blob)
{
	if (blob) {
		if (blob->parent) {
			struct blob **p;

			/* remove blob from list of parent's children */
			for (p = &blob->parent->files; *p != NULL && *p != blob; p = &(*p)->next)
				;
			if (*p == blob)
				*p = blob->next;
		}

		if (blob->file)
			sc_file_free(blob->file);
		if (blob->data)
			free(blob->data);
		free(blob);
	}
}


/* internal: iterate through the blob tree, calling a function for each blob */
static void
pgp_iterate_blobs(struct blob *blob, int level, void (*func)())
{
	if (blob) {
		if (level > 0) {
			struct blob *child = blob->files;

			while (child != NULL) {
				struct blob *next = child->next;

				pgp_iterate_blobs(child, level-1, func);
				child = next;
			}
		}
		func(blob);
	}
}


/* internal: read a blob's contents from card */
static int
pgp_read_blob(sc_card_t *card, struct blob *blob)
{
	if (blob->data != NULL)
		return SC_SUCCESS;
	if (blob->info == NULL)
		return blob->status;

	if (blob->info->get_fn) {	/* readable, top-level DO */
		u8 	buffer[2048];
		size_t	buf_len = (card->caps & SC_CARD_CAP_APDU_EXT)
				  ? sizeof(buffer) : 256;
		int	r = blob->info->get_fn(card, blob->id, buffer, buf_len);

		if (r < 0) {	/* an error occurred */
			blob->status = r;
			return r;
		}

		return pgp_set_blob(blob, buffer, r);
	}
	else {		/* un-readable DO or part of a constrcuted DO */
		return SC_SUCCESS;
	}
}


/*
 * internal: Enumerate contents of a data blob.
 * The OpenPGP card has a TLV encoding according ASN.1 BER-encoding rules.
 */
static int
pgp_enumerate_blob(sc_card_t *card, struct blob *blob)
{
	const u8	*in;
	int		r;

	if (blob->files != NULL)
		return SC_SUCCESS;

	if ((r = pgp_read_blob(card, blob)) < 0)
		return r;

	in = blob->data;

	while ((int) blob->len > (in - blob->data)) {
		unsigned int	cla, tag, tmptag;
		size_t		len;
		const u8	*data = in;
		struct blob	*new;

		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
					&cla, &tag, &len);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Unexpected end of contents\n");
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		/* undo ASN1's split of tag & class */
		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
			cla <<= 8;
		}
		tag |= cla;

		/* create fake file system hierarchy by
		 * using constructed DOs as DF */
		if ((new = pgp_new_blob(card, blob, tag, sc_file_new())) == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		pgp_set_blob(new, data, len);
		in = data + len;
	}

	return SC_SUCCESS;
}


/* internal: find a blob by ID below a given parent, filling its contents when necessary */
static int
pgp_get_blob(sc_card_t *card, struct blob *blob, unsigned int id,
		struct blob **ret)
{
	struct blob		*child;
	int			r;

	if ((r = pgp_enumerate_blob(card, blob)) < 0)
		return r;

	for (child = blob->files; child; child = child->next) {
		if (child->id == id) {
			(void) pgp_read_blob(card, child);
			*ret = child;
			return SC_SUCCESS;
		}
	}

	return SC_ERROR_FILE_NOT_FOUND;
}


/* ABI: SELECT FILE */
static int
pgp_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **ret)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;
	unsigned int	path_start;
	unsigned int	n;

	LOG_FUNC_CALLED(card->ctx);

	if (path->type == SC_PATH_TYPE_DF_NAME)
		LOG_FUNC_RETURN(card->ctx, iso_ops->select_file(card, path, ret));

	if (path->type != SC_PATH_TYPE_PATH)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid path type");

	if (path->len < 2 || (path->len & 1))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid path length");

	/* ignore explicitely mentioned MF at the path's beginning */
	path_start = (memcmp(path->value, "\x3f\x00", 2) == 0) ? 2 : 0;

	/* starting with the MF ... */
	blob = priv->mf;
	/* ... recurse through the tree following the path */
	for (n = path_start; n < path->len; n += 2) {
		unsigned int	id = bebytes2ushort(path->value + n);
		int		r = pgp_get_blob(card, blob, id, &blob);

		if (r < 0) {	/* failure */
			priv->current = NULL;
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	/* success: select file = set "current" pointer to blob found */
	priv->current = blob;

	if (ret)
		sc_file_dup(ret, blob->file);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/* ABI: LIST FILES */
static int
pgp_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;
	unsigned int	k;
	int		r;

	LOG_FUNC_CALLED(card->ctx);

	/* jump to selected file */
	blob = priv->current;

	if (blob->file->type != SC_FILE_TYPE_DF)
		LOG_TEST_RET(card->ctx, SC_ERROR_OBJECT_NOT_VALID,
				"invalid file type");

	if ((r = pgp_enumerate_blob(card, blob)) < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	for (k = 0, blob = blob->files; blob != NULL; blob = blob->next) {
		if (blob->info != NULL && (blob->info->access & READ_MASK) != READ_NEVER) {
			if (k + 2 > buflen)
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);

			ushort2bebytes(buf + k, blob->id);
			k += 2;
		}
	}

	LOG_FUNC_RETURN(card->ctx, k);
}


/* ABI: READ BINARY */
static int
pgp_read_binary(sc_card_t *card, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;
	int		r;

	LOG_FUNC_CALLED(card->ctx);

	/* jump to selected file */
	blob = priv->current;

	if (blob == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

	if (blob->file->type != SC_FILE_TYPE_WORKING_EF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

	if ((r = pgp_read_blob(card, blob)) < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	if (idx > blob->len)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	if (idx + count > blob->len)
		count = blob->len - idx;
	memcpy(buf, blob->data + idx, count);

	LOG_FUNC_RETURN(card->ctx, count);
}


/* ABI: WRITE BINARY */
static int
pgp_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}


/* internal: get public key from card: as DF + sub-wEFs */
static int
pgp_get_pubkey(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	u8		idbuf[2];
	int		r;

	sc_log(card->ctx, "called, tag=%04x\n", tag);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x47, 0x81, 0);
	apdu.lc = 2;
	apdu.data = ushort2bebytes(idbuf, tag);
	apdu.datalen = 2;
	apdu.le = ((buf_len >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : buf_len;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


/* internal: get public key from card: as one wEF */
static int
pgp_get_pubkey_pem(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob, *mod_blob, *exp_blob;
	sc_pkcs15_pubkey_t pubkey;
	u8		*data;
	size_t		len;
	int		r;

	sc_log(card->ctx, "called, tag=%04x\n", tag);
	
	if ((r = pgp_get_blob(card, priv->mf, tag & 0xFFFE, &blob)) < 0
	 || (r = pgp_get_blob(card, blob, 0x7F49, &blob)) < 0
	 || (r = pgp_get_blob(card, blob, 0x0081, &mod_blob)) < 0
	 || (r = pgp_get_blob(card, blob, 0x0082, &exp_blob)) < 0
	 || (r = pgp_read_blob(card, mod_blob)) < 0
	 || (r = pgp_read_blob(card, exp_blob)) < 0)
		LOG_TEST_RET(card->ctx, r, "error getting elements");

	memset(&pubkey, 0, sizeof(pubkey));
	pubkey.algorithm = SC_ALGORITHM_RSA;
	pubkey.u.rsa.modulus.data  = mod_blob->data;
	pubkey.u.rsa.modulus.len   = mod_blob->len;
	pubkey.u.rsa.exponent.data = exp_blob->data;
	pubkey.u.rsa.exponent.len  = exp_blob->len;

	r = sc_pkcs15_encode_pubkey(card->ctx, &pubkey, &data, &len);
	LOG_TEST_RET(card->ctx, r, "public key encoding failed");

	if (len > buf_len)
		len = buf_len;
	memcpy(buf, data, len);
	free(data);

	LOG_FUNC_RETURN(card->ctx, len);
}


/* ABI: GET DATA */
static int
pgp_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	int		r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xCA, tag >> 8, tag);
	apdu.le = ((buf_len >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : buf_len;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


/* ABI: PUT DATA */
static int
pgp_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t buf_len)
{
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}


/* ABI: PIN cmd: verify/change/unblock a PIN */
static int
pgp_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	LOG_FUNC_CALLED(card->ctx);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid PIN type");

	LOG_FUNC_RETURN(card->ctx, iso_ops->pin_cmd(card, data, tries_left));
}


/* ABI: set security environment */
static int
pgp_set_security_env(sc_card_t *card,
		const sc_security_env_t *env, int se_num)
{
	struct pgp_priv_data *priv = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if ((env->flags & SC_SEC_ENV_ALG_PRESENT) && (env->algorithm != SC_ALGORITHM_RSA))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"only RSA algorithm supported");

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || (env->key_ref_len != 1))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"exactly one key reference required");

	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
			"passing file references not supported");

	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		if (env->key_ref[0] != 0x00 && env->key_ref[0] != 0x02) {
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Key reference not compatible with "
				"requested usage");
		}
		break;
	case SC_SEC_OPERATION_DECIPHER:
		if (env->key_ref[0] != 0x01) {
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Key reference not compatible with "
				"requested usage");
		}
		break;
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid operation");
	}

	priv->sec_env = *env;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/* ABI: COMPUTE DIGITAL SIGNATURE */
static int
pgp_compute_signature(sc_card_t *card, const u8 *data,
                size_t data_len, u8 * out, size_t outlen)
{
	struct pgp_priv_data	*priv = DRVDATA(card);
	sc_security_env_t	*env = &priv->sec_env;
	sc_apdu_t		apdu;
	int			r;

	LOG_FUNC_CALLED(card->ctx);

	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid operation");

	switch (env->key_ref[0]) {
	case 0x00: /* signature key */
		/* PSO SIGNATURE */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x9E, 0x9A);
		break;
	case 0x02: /* authentication key */
		/* INTERNAL AUTHENTICATE */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x88, 0, 0);
		break;
	case 0x01:
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
			"invalid key reference");
	}

	apdu.lc = data_len;
	apdu.data = data;
	apdu.datalen = data_len;
	apdu.le = ((outlen >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : outlen;
	apdu.resp    = out;
	apdu.resplen = outlen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


/* ABI: DECIPHER */
static int
pgp_decipher(sc_card_t *card, const u8 *in, size_t inlen,
		u8 *out, size_t outlen)
{
	struct pgp_priv_data	*priv = DRVDATA(card);
	sc_security_env_t	*env = &priv->sec_env;
	sc_apdu_t	apdu;
	u8		*temp = NULL;
	int		r;

	LOG_FUNC_CALLED(card->ctx);

	/* There's some funny padding indicator that must be
	 * prepended... hmm. */
	if (!(temp = malloc(inlen + 1)))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	temp[0] = '\0';
	memcpy(temp + 1, in, inlen);
	in = temp;
	inlen += 1;

	if (env->operation != SC_SEC_OPERATION_DECIPHER) {
		free(temp);
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid operation");
	}

	switch (env->key_ref[0]) {
	case 0x01: /* Decryption key */
		/* PSO DECIPHER */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
		break;
	case 0x00: /* signature key */
	case 0x02: /* authentication key */
	default:
		free(temp);
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid key reference");
	}

	apdu.lc = inlen;
	apdu.data = in;
	apdu.datalen = inlen;
	apdu.le = ((outlen >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : outlen;
	apdu.resp = out;
	apdu.resplen = outlen;

	r = sc_transmit_apdu(card, &apdu);
	free(temp);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


/* ABI: card ctl: perform special card-specific operations */
static int pgp_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	LOG_FUNC_CALLED(card->ctx);

	switch(cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		memmove((sc_serial_number_t *) ptr, &card->serialnr, sizeof(card->serialnr));
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		break;
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}


/* ABI: driver binding stuff */
static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;

	pgp_ops = *iso_ops;
	pgp_ops.match_card	= pgp_match_card;
	pgp_ops.init		= pgp_init;
	pgp_ops.finish		= pgp_finish;
	pgp_ops.select_file	= pgp_select_file;
	pgp_ops.list_files	= pgp_list_files;
	pgp_ops.read_binary	= pgp_read_binary;
	pgp_ops.write_binary	= pgp_write_binary;
	pgp_ops.pin_cmd		= pgp_pin_cmd;
	pgp_ops.get_data	= pgp_get_data;
	pgp_ops.put_data	= pgp_put_data;
	pgp_ops.set_security_env= pgp_set_security_env;
	pgp_ops.compute_signature= pgp_compute_signature;
	pgp_ops.decipher	= pgp_decipher;
	pgp_ops.card_ctl	= pgp_card_ctl;

	return &pgp_drv;
}

struct sc_card_driver *
sc_get_openpgp_driver(void)
{
	return sc_get_driver();
}
