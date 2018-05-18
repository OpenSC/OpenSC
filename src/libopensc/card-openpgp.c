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
 * http://www.g10code.de/docs/openpgp-card-2.1.pdf (minor changes to v2.0)
 * http://www.g10code.de/docs/openpgp-card-3.0.pdf (not yet supported)
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "errors.h"
#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif /* ENABLE_OPENSSL */

static struct sc_atr_table pgp_atrs[] = {
	{ "3b:fa:13:00:ff:81:31:80:45:00:31:c1:73:c0:01:00:00:90:00:b1", NULL, "OpenPGP card v1.0/1.1", SC_CARD_TYPE_OPENPGP_V1, 0, NULL },
	{ "3b:da:18:ff:81:b1:fe:75:1f:03:00:31:c5:73:c0:01:40:00:90:00:0c", NULL, "CryptoStick v1.2 (OpenPGP v2.0)", SC_CARD_TYPE_OPENPGP_V2, 0, NULL },
	{ "3b:da:11:ff:81:b1:fe:55:1f:03:00:31:84:73:80:01:80:00:90:00:e4", NULL, "Gnuk v1.0.x (OpenPGP v2.0)", SC_CARD_TYPE_OPENPGP_GNUK, 0, NULL },
	{ "3b:fc:13:00:00:81:31:fe:15:59:75:62:69:6b:65:79:4e:45:4f:72:33:e1", NULL, "Yubikey NEO (OpenPGP v2.0)", SC_CARD_TYPE_OPENPGP_V2, 0, NULL },
	{ "3b:f8:13:00:00:81:31:fe:15:59:75:62:69:6b:65:79:34:d4", NULL, "Yubikey 4 (OpenPGP v2.1)", SC_CARD_TYPE_OPENPGP_V2, 0, NULL },
	{ "3b:da:18:ff:81:b1:fe:75:1f:03:00:31:f5:73:c0:01:60:00:90:00:1c", NULL, "OpenPGP card V3", SC_CARD_TYPE_OPENPGP_V3, 0, NULL },
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
	OPENPGP_CARD_2_0 = 0x0200,
	OPENPGP_CARD_2_1 = 0x0201,
	OPENPGP_CARD_3_0 = 0x0300,
	OPENPGP_CARD_3_1 = 0x0301,
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

enum _ext_caps {	/* extended capabilities/features */
	EXT_CAP_ALG_ATTR_CHANGEABLE = 0x0004,
	EXT_CAP_PRIVATE_DO          = 0x0008,
	EXT_CAP_C4_CHANGEABLE       = 0x0010,
	EXT_CAP_KEY_IMPORT          = 0x0020,
	EXT_CAP_GET_CHALLENGE       = 0x0040,
	EXT_CAP_SM                  = 0x0080,
	EXT_CAP_CHAINING            = 0x1000,
	EXT_CAP_APDU_EXT            = 0x2000
};

enum _card_state {
	CARD_STATE_UNKNOWN        = 0x00,
	CARD_STATE_INITIALIZATION = 0x03,
	CARD_STATE_ACTIVATED      = 0x05
};

typedef struct pgp_blob {
	struct pgp_blob *	next;	/* pointer to next sibling */
	struct pgp_blob *	parent;	/* pointer to parent */
	struct do_info *info;

	sc_file_t *	file;
	unsigned int	id;
	int		status;

	unsigned char *	data;
	unsigned int	len;
	struct pgp_blob *	files;	/* pointer to 1st child */
} pgp_blob_t;

struct do_info {
	unsigned int	id;		/* ID of the DO in question */

	enum _type	type;		/* constructed DO or not */
	enum _access	access;		/* R/W access levels for the DO */

	/* function to get the DO from the card:
	 * only != NULL is DO if readable and not only a part of a constructed DO */
	int		(*get_fn)(sc_card_t *, unsigned int, u8 *, size_t);
	/* function to write the DO to the card:
	 * only != NULL if DO is writeable under some conditions */
	int		(*put_fn)(sc_card_t *, unsigned int, const u8 *, size_t);
};

static int		pgp_get_card_features(sc_card_t *card);
static int		pgp_finish(sc_card_t *card);
static void		pgp_iterate_blobs(pgp_blob_t *, int, void (*func)());

static int		pgp_get_blob(sc_card_t *card, pgp_blob_t *blob,
				 unsigned int id, pgp_blob_t **ret);
static pgp_blob_t *	pgp_new_blob(sc_card_t *, pgp_blob_t *, unsigned int, sc_file_t *);
static void		pgp_free_blob(pgp_blob_t *);
static int		pgp_get_pubkey(sc_card_t *, unsigned int,
				u8 *, size_t);
static int		pgp_get_pubkey_pem(sc_card_t *, unsigned int,
				u8 *, size_t);

/* The DO holding X.509 certificate is constructed but does not contain a child DO.
 * We should notice this when building fake file system later. */
#define DO_CERT                  0x7f21
/* Control Reference Template of private keys. Ref: Section 4.3.3.7 of OpenPGP card v2 spec.
 * Here we treat them as DOs just for convenience */
#define DO_SIGN                  0xb600
#define DO_ENCR                  0xb800
#define DO_AUTH                  0xa400
/* These DOs do not exist. They are defined and used just for ease of implementation */
#define DO_SIGN_SYM              0xb601
#define DO_ENCR_SYM              0xb801
#define DO_AUTH_SYM              0xa401
/* Private DOs */
#define DO_PRIV1                 0x0101
#define DO_PRIV2                 0x0102
#define DO_PRIV3                 0x0103
#define DO_PRIV4                 0x0104
/* Cardholder information DOs */
#define DO_CARDHOLDER            0x65
#define DO_NAME                  0x5b
#define DO_LANG_PREF             0x5f2d
#define DO_SEX                   0x5f35


/* Maximum length for response buffer when reading pubkey.
 * This value is calculated with 4096-bit key length */
#define MAXLEN_RESP_PUBKEY       527
/* Gnuk only supports 1 key length (2048 bit) */
#define MAXLEN_RESP_PUBKEY_GNUK  271

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
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN2   | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ DO_AUTH,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_AUTH_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_SIGN,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_SIGN_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_ENCR,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_ENCR_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
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
	{ 0x0101, SIMPLE,      READ_ALWAYS | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0102, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x0103, SIMPLE,      READ_PIN2   | WRITE_PIN2,  sc_get_data,        sc_put_data },
	{ 0x0104, SIMPLE,      READ_PIN3   | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x3f00, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ 0x5f2d, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f35, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f48, CONSTRUCTED, READ_NEVER  | WRITE_PIN3,  NULL,               sc_put_data },
	{ 0x5f50, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x5f52, SIMPLE,      READ_ALWAYS | WRITE_NEVER, sc_get_data,        NULL        },
	/* The 7F21 is constructed DO in spec, but in practice, its content can be retrieved
	 * as simple DO (no need to parse TLV). */
	{ DO_CERT, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  sc_get_data,        sc_put_data },
	{ 0x7f48, CONSTRUCTED, READ_NEVER  | WRITE_NEVER, NULL,               NULL        },
	{ 0x7f49, CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, NULL,               NULL        },
	{ DO_AUTH,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	/* The 0xA401, 0xB601, 0xB801 are just symbolic, it does not represent any real DO.
	 * However, their R/W access condition may block the process of importing key in pkcs15init.
	 * So we set their accesses condition as WRITE_PIN3 (writable). */
	{ DO_AUTH_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_SIGN,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_SIGN_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ DO_ENCR,     CONSTRUCTED, READ_ALWAYS | WRITE_NEVER, pgp_get_pubkey,     NULL   },
	{ DO_ENCR_SYM, SIMPLE,      READ_ALWAYS | WRITE_PIN3,  pgp_get_pubkey_pem, NULL   },
	{ 0, 0, 0, NULL, NULL },
};

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))
struct pgp_priv_data {
	pgp_blob_t *		mf;
	pgp_blob_t *		current;	/* currently selected file */

	enum _version		bcd_version;
	struct do_info		*pgp_objects;

	enum _card_state	state;		/* card state */
	enum _ext_caps		ext_caps;	/* extended capabilities */

	size_t			max_challenge_size;
	size_t			max_cert_size;

	sc_security_env_t	sec_env;
};

static int
get_full_pgp_aid(sc_card_t *card, sc_file_t *file)
{
	int r = 0;
	/* explicitly get the full aid */
	r = sc_get_data(card, 0x004F, file->name, sizeof file->name);
	file->namelen = MAX(r, 0);

	return r;
}

/**
 * ABI: check if card's ATR matches one of driver's
 * or if the OpenPGP application is present.
 */
static int
pgp_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, pgp_atrs, &card->type);
	if (i >= 0) {
		card->name = pgp_atrs[i].name;
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	else {
		sc_path_t	partial_aid;
		sc_file_t *file = NULL;

		/* select application "OpenPGP" */
		sc_format_path("D276:0001:2401", &partial_aid);
		partial_aid.type = SC_PATH_TYPE_DF_NAME;
		/* OpenPGP card only supports selection *with* requested FCI */
		i = iso_ops->select_file(card, &partial_aid, &file);
		if (SC_SUCCESS == i) {
			static char card_name[SC_MAX_APDU_BUFFER_SIZE] = "OpenPGP card";
			card->type = SC_CARD_TYPE_OPENPGP_BASE;
			card->name = card_name;
			if (file->namelen != 16)
				(void) get_full_pgp_aid(card, file);
			if (file->namelen == 16) {
				unsigned char major = file->name[6];
				unsigned char minor = file->name[7];
				switch (major) {
					case 1:
						card->type = SC_CARD_TYPE_OPENPGP_V1;
						break;
					case 2:
						card->type = SC_CARD_TYPE_OPENPGP_V2;
						break;
					case 3:
						card->type = SC_CARD_TYPE_OPENPGP_V3;
						break;
					default:
						break;
				}
				snprintf(card_name, sizeof(card_name), "OpenPGP card V%u.%u", major, minor);
			}
			sc_file_free(file);
			return 1;
		}
	}
	return 0;
}


#define BCD2CHAR(x) (((((x) & 0xF0) >> 4) * 10) + ((x) & 0x0F))

/**
 * ABI: initialize driver.
 */
static int
pgp_init(sc_card_t *card)
{
	struct pgp_priv_data *priv;
	sc_path_t	path;
	sc_file_t	*file = NULL;
	struct do_info	*info;
	int		r;
	pgp_blob_t 	*child = NULL;

	LOG_FUNC_CALLED(card->ctx);

	priv = calloc (1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;

	card->cla = 0x00;

	/* select application "OpenPGP" */
	sc_format_path("D276:0001:2401", &path);
	path.type = SC_PATH_TYPE_DF_NAME;
	if ((r = iso_ops->select_file(card, &path, &file)) < 0) {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* defensive programming check */
	if (!file)   {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}

	if (file->namelen != 16) {
		/* explicitly get the full aid */
		r = get_full_pgp_aid(card, file);
		if (r < 0) {
			pgp_finish(card);
			return r;
		}
	}

	/* read information from AID */
	if (file->namelen == 16) {
		/* OpenPGP card spec 1.1 & 2.0, section 4.2.1 & 4.1.2.1 */
		priv->bcd_version = bebytes2ushort(file->name + 6);
		card->version.fw_major = card->version.hw_major = BCD2CHAR(file->name[6]);
		card->version.fw_minor = card->version.hw_minor = BCD2CHAR(file->name[7]);

		/* kludge: get card's serial number from manufacturer ID + serial number */
		memcpy(card->serialnr.value, file->name + 8, 6);
		card->serialnr.len = 6;
	} else {
		/* set detailed card version */
		switch (card->type) {
			case SC_CARD_TYPE_OPENPGP_V3:
				priv->bcd_version = OPENPGP_CARD_3_0;
				break;
			case SC_CARD_TYPE_OPENPGP_GNUK:
			case SC_CARD_TYPE_OPENPGP_V2:
				priv->bcd_version = OPENPGP_CARD_2_0;
				break;
			default:
				priv->bcd_version = OPENPGP_CARD_1_1;
				break;
		}
	}

	/* set pointer to correct list of card objects */
	if (priv->bcd_version < OPENPGP_CARD_2_0) {
		priv->pgp_objects = pgp1_objects;
	} else {
		priv->pgp_objects = pgp2_objects;
	}

	/* change file path to MF for re-use in MF */
	sc_format_path("3f00", &file->path);

	/* set up the root of our fake file tree */
	priv->mf = pgp_new_blob(card, NULL, 0x3f00, file);
	if (!priv->mf) {
		pgp_finish(card);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	/* select MF */
	priv->current = priv->mf;

	/* populate MF - add matching blobs listed in the pgp_objects table */
	for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
		if (((info->access & READ_MASK) != READ_NEVER) &&
			(info->get_fn != NULL)) {
			child = pgp_new_blob(card, priv->mf, info->id, sc_file_new());

			/* catch out of memory condition */
			if (child == NULL) {
				pgp_finish(card);
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			}
		}
	}

	/* get card_features from ATR & DOs */
	pgp_get_card_features(card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/**
 * Internal: get features of the card: capabilities, ...
 */
static int
pgp_get_card_features(sc_card_t *card)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	unsigned char *hist_bytes = card->atr.value;
	size_t atr_len = card->atr.len;
	size_t i;
	pgp_blob_t *blob, *blob6e, *blob73;

	/* parse card capabilities from historical bytes */
	for (i = 0; (i < atr_len) && (hist_bytes[i] != 0x73); i++)
		;
	/* IS07816-4 hist bytes 3rd function table */
	if ((hist_bytes[i] == 0x73) && (atr_len > i+3)) {
		/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
		if (hist_bytes[i+3] & 0x40) {
			card->caps |= SC_CARD_CAP_APDU_EXT;
			priv->ext_caps |= EXT_CAP_APDU_EXT;
		}
		/* bit 0x80 in byte 3 of TL 0x73 means "Command chaining" */
		if (hist_bytes[i+3] & 0x80)
			priv->ext_caps |= EXT_CAP_CHAINING;
	}

	if (priv->bcd_version >= OPENPGP_CARD_2_0) {
		/* get card capabilities from "historical bytes" DO */
		if ((pgp_get_blob(card, priv->mf, 0x5f52, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->data[0] == 0x00)) {

			/* find beginning of "interesting" bytes */
			for (i = 0; (i < blob->len) && (blob->data[i] != 0x73); i++)
				;
			/* IS07816-4 hist bytes 3rd function table */
			if ((blob->data[i] == 0x73) && (blob->len > i+3)) {
				/* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
				if (blob->data[i+3] & 0x40) {
					card->caps |= SC_CARD_CAP_APDU_EXT;
					priv->ext_caps |= EXT_CAP_APDU_EXT;
				}
				/* bit 0x80 in byte 3 of TL 0x73 means "Command chaining" */
				if (blob->data[i+3] & 0x80)
					priv->ext_caps |= EXT_CAP_CHAINING;
			}

			/* get card status from historical bytes status indicator */
			if ((blob->data[0] == 0x00) && (blob->len >= 4))
				priv->state = blob->data[blob->len-3];
		}
	}

	if (priv->bcd_version >= OPENPGP_CARD_3_1) {
		card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;
	}

	if ((pgp_get_blob(card, priv->mf, 0x006e, &blob6e) >= 0) &&
	    (pgp_get_blob(card, blob6e, 0x0073, &blob73) >= 0)) {

		/* get "extended capabilities" DO */
		if ((pgp_get_blob(card, blob73, 0x00c0, &blob) >= 0) &&
		    (blob->data != NULL) && (blob->len > 0)) {
			/* in v2.0 bit 0x04 in first byte means "algorithm attributes changeable" */
			if ((blob->data[0] & 0x04) &&
					(priv->bcd_version >= OPENPGP_CARD_2_0))
				priv->ext_caps |= EXT_CAP_ALG_ATTR_CHANGEABLE;
			/* bit 0x08 in first byte means "support for private use DOs" */
			if (blob->data[0] & 0x08)
				priv->ext_caps |= EXT_CAP_PRIVATE_DO;
			/* bit 0x10 in first byte means "support for CHV status byte changeable" */
			if (blob->data[0] & 0x10)
				priv->ext_caps |= EXT_CAP_C4_CHANGEABLE;
			/* bit 0x20 in first byte means "support for Key Import" */
			if (blob->data[0] & 0x20)
				priv->ext_caps |= EXT_CAP_KEY_IMPORT;
			/* bit 0x40 in first byte means "support for Get Challenge" */
			if (blob->data[0] & 0x40) {
				card->caps |= SC_CARD_CAP_RNG;
				priv->ext_caps |= EXT_CAP_GET_CHALLENGE;
			}
			/* in v2.0 bit 0x80 in first byte means "support Secure Messaging" */
			if ((blob->data[0] & 0x80) &&
					(priv->bcd_version >= OPENPGP_CARD_2_0))
				priv->ext_caps |= EXT_CAP_SM;

			if ((priv->bcd_version >= OPENPGP_CARD_2_0) && (blob->len >= 10)) {
				/* max. challenge size is at bytes 3-4 */
				priv->max_challenge_size = bebytes2ushort(blob->data + 2);
				/* max. cert size it at bytes 5-6 */
				priv->max_cert_size = bebytes2ushort(blob->data + 4);
				if (priv->bcd_version < OPENPGP_CARD_3_0) {
					/* max. send/receive sizes are at bytes 7-8 resp. 9-10 */
					card->max_send_size = bebytes2ushort(blob->data + 6);
					card->max_recv_size = bebytes2ushort(blob->data + 8);
				}
				/* TODO read Extended length information from DO 7F66 in OpenPGP 3.0 and later */
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
			/* OpenPGP card spec 1.1 & 2.0, section 7.2.9 & 7.2.10 */
			flags = SC_ALGORITHM_RSA_PAD_PKCS1;
			flags |= SC_ALGORITHM_RSA_HASH_NONE;
			/* Can be generated in card */
			flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

			if ((pgp_get_blob(card, blob73, i, &blob) >= 0) &&
				(blob->data != NULL) && (blob->len >= 4)) {
				if (blob->data[0] == 0x01) {	/* Algorithm ID [RFC4880]: RSA */
					unsigned int keylen = bebytes2ushort(blob->data + 1);  /* Measured in bit */

					_sc_card_add_rsa_alg(card, keylen, flags, 0);
				}
			}
		}
	}

	return SC_SUCCESS;
}


/**
 * ABI: terminate driver.
 */
static int
pgp_finish(sc_card_t *card)
{
	if (card != NULL) {
		struct pgp_priv_data *priv = DRVDATA(card);

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


/**
 * Internal: fill a blob's data.
 */
static int
pgp_set_blob(pgp_blob_t *blob, const u8 *data, size_t len)
{
	if (blob->data)
		free(blob->data);
	blob->data = NULL;
	blob->len    = 0;
	blob->status = 0;

	if (len > 0) {
		void *tmp = calloc(len, 1);

		if (tmp == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		blob->data = tmp;
		blob->len  = (unsigned int)len;
		if (data != NULL)
			memcpy(blob->data, data, len);
	}

	if (blob->file)
		blob->file->size = len;

	return SC_SUCCESS;
}


/**
 * Internal: implement Access Control List for emulated file.
 * The Access Control is derived from the DO access permission.
 **/
static void
pgp_attach_acl(sc_card_t *card, sc_file_t *file, struct do_info *info)
{
	unsigned int method = SC_AC_NONE;
	unsigned long key_ref = SC_AC_KEY_REF_NONE;

	/* Write access */
	switch (info->access & WRITE_MASK) {
	case WRITE_NEVER:
		method = SC_AC_NEVER;
		break;
	case WRITE_PIN1:
		method = SC_AC_CHV;
		key_ref = 0x01;
		break;
	case WRITE_PIN2:
		method = SC_AC_CHV;
		key_ref = 0x02;
		break;
	case WRITE_PIN3:
		method = SC_AC_CHV;
		key_ref = 0x03;
		break;
	}

	if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
		sc_file_add_acl_entry(file, SC_AC_OP_WRITE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE, method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_CREATE, method, key_ref);
	}
	else {
		/* When SC_AC_OP_DELETE is absent, we need to provide
		 * SC_AC_OP_DELETE_SELF for sc_pkcs15init_delete_by_path() */
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE_SELF, method, key_ref);
	}

	method = SC_AC_NONE;
	key_ref = SC_AC_KEY_REF_NONE;
	/* Read access */
	switch (info->access & READ_MASK) {
	case READ_NEVER:
		method = SC_AC_NEVER;
		break;
	case READ_PIN1:
		method = SC_AC_CHV;
		key_ref = 0x01;
		break;
	case READ_PIN2:
		method = SC_AC_CHV;
		key_ref = 0x02;
		break;
	case READ_PIN3:
		method = SC_AC_CHV;
		key_ref = 0x03;
		break;
	}

	if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
		sc_file_add_acl_entry(file, SC_AC_OP_READ, method, key_ref);
	}
}


/**
 * Internal: append a blob to the list of children of a given parent blob.
 */
static pgp_blob_t *
pgp_new_blob(sc_card_t *card, pgp_blob_t *parent, unsigned int file_id,
		sc_file_t *file)
{
	pgp_blob_t *blob = NULL;

	if (file == NULL)
		return NULL;

	if ((blob = calloc(1, sizeof(pgp_blob_t))) != NULL) {
		struct pgp_priv_data *priv = DRVDATA(card);
		struct do_info *info;

		blob->file = file;

		blob->file->type         = SC_FILE_TYPE_WORKING_EF; /* default */
		blob->file->ef_structure = SC_FILE_EF_TRANSPARENT;
		blob->file->id           = file_id;

		blob->id     = file_id;
		blob->parent = parent;

		if (parent != NULL) {
			pgp_blob_t **p;

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
			/* FIXME sc_format_path expects an hex string of a file
			 * identifier. ushort2bebytes instead delivers a two bytes binary
			 * string */
			sc_format_path((char *) ushort2bebytes(id_str, file_id), &blob->file->path);
		}

		/* find matching DO info: set file type depending on it */
		for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
			if (info->id == file_id) {
				blob->info = info;
				blob->file->type = blob->info->type;
				pgp_attach_acl(card, blob->file, info);
				break;
			}
		}
	}

	return blob;
}


/**
 * Internal: free a blob including its content.
 */
static void
pgp_free_blob(pgp_blob_t *blob)
{
	if (blob) {
		if (blob->parent) {
			pgp_blob_t **p;

			/* remove blob from list of parent's children */
			for (p = &blob->parent->files; *p != NULL && *p != blob; p = &(*p)->next)
				;
			if (*p == blob)
				*p = blob->next;
		}

		sc_file_free(blob->file);
		if (blob->data)
			free(blob->data);
		free(blob);
	}
}


/**
 * Internal: iterate through the blob tree, calling a function for each blob.
 */
static void
pgp_iterate_blobs(pgp_blob_t *blob, int level, void (*func)())
{
	if (blob) {
		if (level > 0) {
			pgp_blob_t *child = blob->files;

			while (child != NULL) {
				pgp_blob_t *next = child->next;

				pgp_iterate_blobs(child, level-1, func);
				child = next;
			}
		}
		func(blob);
	}
}


/**
 * Internal: read a blob's contents from card.
 */
static int
pgp_read_blob(sc_card_t *card, pgp_blob_t *blob)
{
	struct pgp_priv_data *priv = DRVDATA(card);

	if (blob->data != NULL)
		return SC_SUCCESS;
	if (blob->info == NULL)
		return blob->status;

	if (blob->info->get_fn) {	/* readable, top-level DO */
		u8 	buffer[2048];
		size_t	buf_len = sizeof(buffer);
		int r = SC_SUCCESS;

		/* buffer length for certificate */
		if (blob->id == DO_CERT && priv->max_cert_size > 0) {
			buf_len = MIN(priv->max_cert_size, sizeof(buffer));
		}

		/* buffer length for Gnuk pubkey */
		if (card->type == SC_CARD_TYPE_OPENPGP_GNUK &&
		    (blob->id == DO_AUTH ||
		     blob->id == DO_SIGN ||
		     blob->id == DO_ENCR ||
		     blob->id == DO_AUTH_SYM ||
		     blob->id == DO_SIGN_SYM ||
		     blob->id == DO_ENCR_SYM)) {
			buf_len = MAXLEN_RESP_PUBKEY_GNUK;
		}

		r = blob->info->get_fn(card, blob->id, buffer, buf_len);

		if (r < 0) {	/* an error occurred */
			blob->status = r;
			return r;
		}

		return pgp_set_blob(blob, buffer, r);
	}
	else {		/* un-readable DO or part of a constructed DO */
		return SC_SUCCESS;
	}
}


/*
 * Internal: enumerate contents of a data blob.
 * The OpenPGP card has a TLV encoding according ASN.1 BER-encoding rules.
 */
static int
pgp_enumerate_blob(sc_card_t *card, pgp_blob_t *blob)
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
		pgp_blob_t	*new;

		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
					&cla, &tag, &len);
		if (r < 0 || data == NULL) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Unexpected end of contents\n");
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		/* undo ASN1's split of tag & class */
		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
			cla <<= 8;
		}
		tag |= cla;

		/* Awful hack for composite DOs that have
		 * a TLV with the DO's id encompassing the
		 * entire blob. Example: Yubikey Neo */
		if (tag == blob->id) {
			in = data;
			continue;
		}

		/* create fake file system hierarchy by
		 * using constructed DOs as DF */
		if ((new = pgp_new_blob(card, blob, tag, sc_file_new())) == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		pgp_set_blob(new, data, len);
		in = data + len;
	}

	return SC_SUCCESS;
}


/**
 * Internal: find a blob by ID below a given parent, filling its contents when necessary.
 */
static int
pgp_get_blob(sc_card_t *card, pgp_blob_t *blob, unsigned int id,
		pgp_blob_t **ret)
{
	pgp_blob_t		*child;
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

	/* This part is for "NOT FOUND" cases */

	/* Special case:
	 * Gnuk does not have default value for children of DO 65 (DOs 5B, 5F2D, 5F35)
	 * So, if these blob was not found, we create it. */
	if (blob->id == DO_CARDHOLDER && (id == DO_NAME || id == DO_LANG_PREF || id == DO_SEX)) {
		sc_log(card->ctx, "Create blob %X under %X", id, blob->id);
		child = pgp_new_blob(card, blob, id, sc_file_new());
		if (child) {
			pgp_set_blob(child, NULL, 0);
			*ret = child;
			return SC_SUCCESS;
		}
		else
			sc_log(card->ctx,
			       "Not enough memory to create blob for DO %X",
			       id);
	}

	return SC_ERROR_FILE_NOT_FOUND;
}


/**
 * Internal: search recursively for a blob by ID below a given root.
 */
static int
pgp_seek_blob(sc_card_t *card, pgp_blob_t *root, unsigned int id,
		pgp_blob_t **ret)
{
	pgp_blob_t	*child;
	int			r;

	if ((r = pgp_get_blob(card, root, id, ret)) == 0)
		/* the sought blob is right under root */
		return r;

	/* not found, seek deeper */
	for (child = root->files; child; child = child->next) {
		/* The DO of SIMPLE type or the DO holding certificate
		 * does not contain children */
		if ((child->info && child->info->type == SIMPLE) || child->id == DO_CERT)
			continue;
		r = pgp_seek_blob(card, child, id, ret);
		if (r == 0)
			return r;
	}

	return SC_ERROR_FILE_NOT_FOUND;
}


/**
 * Internal: find a blob by tag - pgp_seek_blob with optimizations.
 */
static pgp_blob_t *
pgp_find_blob(sc_card_t *card, unsigned int tag)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *blob = NULL;
	int r;

	/* check if current selected blob is which we want to test */
	if (priv->current->id == tag) {
		return priv->current;
	}
	/* look for the blob representing the DO */
	r = pgp_seek_blob(card, priv->mf, tag, &blob);
	if (r < 0) {
		sc_log(card->ctx, "Failed to seek the blob representing the tag %04X. Error %d.", tag, r);
		return NULL;
	}
	return blob;
}


/**
 * Internal: get info for a specific tag.
 */
static struct do_info *
pgp_get_info_by_tag(sc_card_t *card, unsigned int tag)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct do_info *info;

	for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++)
		if (tag == info->id)
			return info;

	return NULL;
}


/**
 * Internal: strip out the parts of PKCS15 file layout in the path.
 * Get the reduced version which is understood by the OpenPGP card driver.
 * Return the index whose preceding part will be ignored.
 **/
static unsigned int
pgp_strip_path(sc_card_t *card, const sc_path_t *path)
{
	unsigned int start_point = 0;
	/* start_point will move through the path string */
	if (path->len == 0)
		return 0;

	/* ignore 3F00 (MF) at the beginning */
	start_point = (memcmp(path->value, "\x3f\x00", 2) == 0) ? 2 : 0;
	/* strip path of PKCS15-App DF (5015) */
	start_point += (memcmp(path->value + start_point, "\x50\x15", 2) == 0) ? 2 : 0;
	return start_point;
}


/**
 * ABI: SELECT FILE.
 */
static int
pgp_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **ret)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t	*blob;
	unsigned int	path_start = 0;
	unsigned int	n;
	sc_path_t dummy_path;

	LOG_FUNC_CALLED(card->ctx);

	if (path->type == SC_PATH_TYPE_DF_NAME)
		LOG_FUNC_RETURN(card->ctx, iso_ops->select_file(card, path, ret));

	if (path->len < 2 || (path->len & 1))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid path length");

	if (path->type == SC_PATH_TYPE_FILE_ID && path->len != 2)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid path type");

	/* Due to pkcs15init implementation, sometimes a file at path "11001101"
	 * need to be written (one use case is when importing key&cert from p12 file).
	 * This file does not exist in OpenPGP but pkcs15 requires that
	 * writing this file must be successful.
	 * So, we pretend that selecting & writing this file is successful.
	 * The "11001101"is defined in sc_pkcs15emu_get_df() function, pkcs15-sync.c file. */
	sc_format_path("11001101", &dummy_path);
	if (sc_compare_path(path, &dummy_path)) {
		if (ret != NULL) {
			*ret = sc_file_new();
			/* One use case of this dummy file is after writing certificate in pkcs15init.
			 * So we set its size to be the same as max certificate size the card supports. */
			(*ret)->size = priv->max_cert_size;
		}
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	/* ignore explicitly mentioned MF at the path's beginning */
	path_start = pgp_strip_path(card, path);

	/* starting with the MF ... */
	blob = priv->mf;
	/* ... recurse through the tree following the path */
	for (n = path_start; n < path->len; n += 2) {
		unsigned int	id = bebytes2ushort(path->value + n);
		int		r = pgp_get_blob(card, blob, id, &blob);

		/* This file ID is referred when importing key&certificate via pkcs15init, like above.
		 * We pretend to successfully find this inexistent file. */
		if (id == 0x4402 || id == 0x5f48) {
			if (ret == NULL)
				/* No need to return file */
				LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

			/* Else, need to return file */
			*ret = sc_file_new();
			(*ret)->size = priv->max_cert_size;
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}

		if (r < 0) {	/* failure */
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	/* success: select file = set "current" pointer to blob found */
	priv->current = blob;

	if (ret)
		sc_file_dup(ret, blob->file);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/**
 * ABI: LIST FILES.
 */
static int
pgp_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t	*blob;
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

static int
pgp_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	struct pgp_priv_data *priv = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (0 == (priv->ext_caps & EXT_CAP_GET_CHALLENGE)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	if (priv->max_challenge_size > 0 && len > priv->max_challenge_size) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);
	}

	LOG_FUNC_RETURN(card->ctx, iso_ops->get_challenge(card, rnd, len));
}


/**
 * ABI: READ BINARY.
 */
static int
pgp_read_binary(sc_card_t *card, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t	*blob;
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

	LOG_FUNC_RETURN(card->ctx, (int)count);
}


/**
 * ABI: WRITE BINARY.
 */
static int
pgp_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}


/**
 * Internal: get public key from card: as DF + sub-wEFs.
 */
static int
pgp_get_pubkey(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	u8 apdu_case = (card->type == SC_CARD_TYPE_OPENPGP_GNUK)
			? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_4;
	u8		idbuf[2];
	int		r;

	sc_log(card->ctx, "called, tag=%04x\n", tag);

	sc_format_apdu(card, &apdu, apdu_case, 0x47, 0x81, 0);
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

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}


/**
 * Internal: get public key from card: as one wEF.
 */
static int
pgp_get_pubkey_pem(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t	*blob, *mod_blob, *exp_blob;
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

	LOG_FUNC_RETURN(card->ctx, (int)len);
}


/**
 * ABI: GET DATA.
 */
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

	/* For Gnuk card, if there is no certificate, it returns error instead of empty data.
	 * So, for this case, we ignore error and consider success */
	if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND && card->type == SC_CARD_TYPE_OPENPGP_GNUK
        && (tag == DO_CERT || tag == DO_PRIV1 || tag == DO_PRIV2 || tag == DO_PRIV3 || tag == DO_PRIV4)) {
		r = SC_SUCCESS;
		apdu.resplen = 0;
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}


/**
 * Internal: write certificate for Gnuk.
 */
static int
gnuk_write_certificate(sc_card_t *card, const u8 *buf, size_t length)
{
	size_t i = 0;
	sc_apdu_t apdu;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	/* If null data is passed, delete certificate */
	if (buf == NULL || length == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xD6, 0x85, 0);
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		/* Check response */
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "Certificate writing failed");
	}

	/* Ref: gnuk_put_binary_libusb.py and gnuk_token.py in Gnuk source tree */
	/* Split data to segments of 256 bytes. Send each segment via command chaining,
	 * with particular P1 byte for each segment */
	for (i = 0; i*256 < length; i++) {
		u8 *part = (u8 *)buf + i*256;
		size_t plen = MIN(length - i*256, 256);
		u8 roundbuf[256];	/* space to build APDU data with even length for Gnuk */

		sc_log(card->ctx,
		       "Write part %"SC_FORMAT_LEN_SIZE_T"u from offset 0x%"SC_FORMAT_LEN_SIZE_T"X, len %"SC_FORMAT_LEN_SIZE_T"u",
		       i+1, i*256, plen);

		/* 1st chunk: P1 = 0x85, further chunks: P1 = chunk no */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6, (i == 0) ? 0x85 : i, 0);
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
		apdu.data = part;
		apdu.datalen = apdu.lc = plen;

		/* If the last part has odd length, we add zero padding to make it even.
		 * Gnuk does not allow data with odd length */
		if (plen < 256 && (plen % 2) != 0) {
			memcpy(roundbuf, part, plen);
			roundbuf[plen++] = 0;
			apdu.data = roundbuf;
			apdu.datalen = apdu.lc = plen;
		}

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		/* Check response */
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "UPDATE BINARY returned error");
	}

	LOG_FUNC_RETURN(card->ctx, (int)length);
}


/**
 * Internal: use PUT DATA command to write.
 */
static int
pgp_put_data_plain(sc_card_t *card, unsigned int tag, const u8 *buf, size_t buf_len)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	sc_apdu_t apdu;
	u8 ins = 0xDA;
	u8 p1 = tag >> 8;
	u8 p2 = tag & 0xFF;
	u8 apdu_case = (card->type == SC_CARD_TYPE_OPENPGP_GNUK)
			? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_3;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* Extended Header list (004D DO) needs a variant of PUT DATA command */
	if (tag == 0x004D) {
		ins = 0xDB;
		p1 = 0x3F;
		p2 = 0xFF;
	}

	/* build APDU */
	if (buf != NULL && buf_len > 0) {
		sc_format_apdu(card, &apdu, apdu_case, ins, p1, p2);

		/* if card/reader does not support extended APDUs, but chaining, then set it */
		if (((card->caps & SC_CARD_CAP_APDU_EXT) == 0) && (priv->ext_caps & EXT_CAP_CHAINING))
			apdu.flags |= SC_APDU_FLAGS_CHAINING;

		apdu.data = (u8 *)buf;
		apdu.datalen = buf_len;
		apdu.lc = buf_len;
	}
	else {
		/* This case is to empty DO */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, ins, p1, p2);
	}

	/* send APDU to card */
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	/* check response */
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	LOG_FUNC_RETURN(card->ctx, (int)buf_len);
}


/**
 * ABI: PUT DATA.
 */
static int
pgp_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t buf_len)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *affected_blob = NULL;
	struct do_info *dinfo = NULL;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* check if the tag is writable */
	if (priv->current->id != tag)
		affected_blob = pgp_find_blob(card, tag);

	/* Non-readable DOs have no represented blob, we have to check from pgp_get_info_by_tag */
	if (affected_blob == NULL)
		dinfo = pgp_get_info_by_tag(card, tag);
	else
		dinfo = affected_blob->info;

	if (dinfo == NULL) {
		sc_log(card->ctx, "The DO %04X does not exist.", tag);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	else if ((dinfo->access & WRITE_MASK) == WRITE_NEVER) {
		sc_log(card->ctx, "DO %04X is not writable.", tag);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_ALLOWED);
	}

	/* Check data size.
	 * We won't check other DOs than 7F21 (certificate), because their capacity
	 * is hard-coded and may change in various version of the card.
	 * If we check here, the driver may be stuck to a limit version number of card.
	 * 7F21 size is soft-coded, so we can check it. */
	if (tag == DO_CERT && buf_len > priv->max_cert_size) {
		sc_log(card->ctx,
		       "Data size %"SC_FORMAT_LEN_SIZE_T"u exceeds DO size limit %"SC_FORMAT_LEN_SIZE_T"u.",
		       buf_len, priv->max_cert_size);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);
	}

	if (tag == DO_CERT && card->type == SC_CARD_TYPE_OPENPGP_GNUK) {
		/* Gnuk need a special way to write certificate. */
		r = gnuk_write_certificate(card, buf, buf_len);
	}
	else {
		r = pgp_put_data_plain(card, tag, buf, buf_len);
	}

	/* instruct more in case of error */
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Please verify PIN first.");
	}
	LOG_TEST_RET(card->ctx, r, "PUT DATA returned error");

	if (affected_blob) {
		/* update the corresponding file */
		sc_log(card->ctx, "Updating the corresponding blob data");
		r = pgp_set_blob(affected_blob, buf, buf_len);
		if (r < 0)
			sc_log(card->ctx, "Failed to update blob %04X. Error %d.", affected_blob->id, r);
		/* pgp_set_blob()'s failures do not impact pgp_put_data()'s result */
	}

	LOG_FUNC_RETURN(card->ctx, (int)buf_len);
}


/**
 * ABI: PIN cmd: verify/change/unblock a PIN.
 */
static int
pgp_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct pgp_priv_data *priv = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid PIN type");

	/* In general, the PIN Reference is extracted from the key-id,
	 * for example, CHV0 -> Ref=0, CHV1 -> Ref=1.
	 * However, in the case of OpenGPG, the PIN Ref to compose APDU
	 * must be 81, 82, 83.
	 * So, if we receive Ref=1, Ref=2, we must convert to 81, 82...
	 * In OpenPGP v1, the PINs are named CHV1, CHV2, CHV3.
	 * In v2, they are named PW1, PW3 (PW1 operates in 2 modes).
	 *
	 * The PIN references (P2 in APDU) for "VERIFY" are the same in both versions:
	 * 81 (CHV1 or PW1), 82 (CHV2 or PW1-mode 2), 83 (CHV3 or PW3),
	 * On the other hand from version 2.0 "CHANGE REFERENCE DATA" and
	 * "RESET RETRY COUNTER" don't support PW1-mode 2 (82) and need this
	 * value changed to PW1 (81).
	 * Both of these commands also differ between card versions in that
	 * v1 cards can use only implicit old PIN or CHV3 test for both commands
	 * whereas v2 can use both implicit (for PW3) and explicit
	 * (for special "Resetting Code") PIN test for "RESET RETRY COUNTER"
	 * and only explicit test for "CHANGE REFERENCE DATA".
	 *
	 * Note that if this function is called from sc_pkcs15_verify_pin() in pkcs15-pin.c,
	 * the Ref is already 81, 82, 83.
	 */

	/* convert the PIN Reference if needed */
	data->pin_reference |= 0x80;

	/* check version-dependent constraints */
	if (data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK) {
		if (priv->bcd_version >= OPENPGP_CARD_2_0) {
			if (data->pin_reference == 0x82)
				data->pin_reference = 0x81;

			if (data->cmd == SC_PIN_CMD_CHANGE) {
				if (data->pin1.len == 0 &&
				    !(data->flags & SC_PIN_CMD_USE_PINPAD))
					LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
						     "v2 cards don't support implicit old PIN for PIN change.");

				data->flags &= ~SC_PIN_CMD_IMPLICIT_CHANGE;
			}
		} else {
			if (data->pin1.len != 0) {
				sc_log(card->ctx,
				       "v1 cards don't support explicit old or CHV3 PIN, PIN ignored.");
				sc_log(card->ctx,
				       "please make sure that you have verified the relevant PIN first.");
				data->pin1.len = 0;
			}

			data->flags |= SC_PIN_CMD_IMPLICIT_CHANGE;
		}
	}

	if (data->cmd == SC_PIN_CMD_UNBLOCK && data->pin2.len == 0 &&
	    !(data->flags & SC_PIN_CMD_USE_PINPAD))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
			     "new PIN must be provided for unblock operation.");

	/* ensure pin_reference is 81, 82, 83 */
	if (!(data->pin_reference == 0x81 || data->pin_reference == 0x82 || data->pin_reference == 0x83)) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
					 "key-id should be 1, 2, 3.");
	}
	LOG_FUNC_RETURN(card->ctx, iso_ops->pin_cmd(card, data, tries_left));
}


int pgp_logout(struct sc_card *card)
{
	int r = SC_SUCCESS;
	struct pgp_priv_data *priv = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (priv->bcd_version >= OPENPGP_CARD_3_1) {
		unsigned char pin_reference;
		for (pin_reference = 0x81; pin_reference <= 0x83; pin_reference++) {
			int tmp = iso7816_logout(card, pin_reference);
			if (r == SC_SUCCESS) {
				r = tmp;
			}
		}
	} else {
		sc_path_t path;
		sc_file_t *file = NULL;

		/* select application "OpenPGP" */
		sc_format_path("D276:0001:2401", &path);
		path.type = SC_PATH_TYPE_DF_NAME;
		r = iso_ops->select_file(card, &path, &file);
		sc_file_free(file);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * ABI: set security environment.
 */
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

	sc_log(card->ctx, "Key ref %d", env->key_ref[0]);
	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		sc_log(card->ctx, "Operation: Sign.");
		if (env->key_ref[0] != 0x00 && env->key_ref[0] != 0x02) {
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Key reference not compatible with "
				"requested usage");
		}
		break;
	case SC_SEC_OPERATION_DECIPHER:
		sc_log(card->ctx, "Operation: Decipher.");
		/* we allow key ref 2 (auth key) to be used for deciphering */
		if (env->key_ref[0] != 0x01 && env->key_ref[0] != 0x02) {
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


/**
 * ABI: COMPUTE DIGITAL SIGNATURE.
 */
static int
pgp_compute_signature(sc_card_t *card, const u8 *data,
                size_t data_len, u8 * out, size_t outlen)
{
	struct pgp_priv_data	*priv = DRVDATA(card);
	sc_security_env_t	*env = &priv->sec_env;
	sc_apdu_t		apdu;
	u8 apdu_case = (card->type == SC_CARD_TYPE_OPENPGP_GNUK)
			? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_4;
	int			r;

	LOG_FUNC_CALLED(card->ctx);

	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid operation");

	switch (env->key_ref[0]) {
	case 0x00: /* signature key */
		/* PSO SIGNATURE */
		sc_format_apdu(card, &apdu, apdu_case, 0x2A, 0x9E, 0x9A);
		break;
	case 0x02: /* authentication key */
		/* INTERNAL AUTHENTICATE */
		sc_format_apdu(card, &apdu, apdu_case, 0x88, 0, 0);
		break;
	case 0x01:
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
			"invalid key reference");
	}

	/* if card/reader does not support extended APDUs, but chaining, then set it */
	if (((card->caps & SC_CARD_CAP_APDU_EXT) == 0) && (priv->ext_caps & EXT_CAP_CHAINING))
		apdu.flags |= SC_APDU_FLAGS_CHAINING;

	apdu.lc = data_len;
	apdu.data = (u8 *)data;
	apdu.datalen = data_len;
	apdu.le = ((outlen >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : outlen;
	apdu.resp    = out;
	apdu.resplen = outlen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}


/**
 * ABI: DECIPHER.
 */
static int
pgp_decipher(sc_card_t *card, const u8 *in, size_t inlen,
		u8 *out, size_t outlen)
{
	struct pgp_priv_data	*priv = DRVDATA(card);
	sc_security_env_t	*env = &priv->sec_env;
	sc_apdu_t	apdu;
	u8 apdu_case = SC_APDU_CASE_4;
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
	case 0x02: /* authentication key */
		/* PSO DECIPHER */
		sc_format_apdu(card, &apdu, apdu_case, 0x2A, 0x80, 0x86);
		break;
	case 0x00: /* signature key */
	default:
		free(temp);
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS,
				"invalid key reference");
	}

	/* Gnuk only supports short APDU, so we need to use command chaining */
	if (card->type == SC_CARD_TYPE_OPENPGP_GNUK) {
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	}
	/* if card/reader does not support extended APDUs, but chaining, then set it */
	if (((card->caps & SC_CARD_CAP_APDU_EXT) == 0) && (priv->ext_caps & EXT_CAP_CHAINING))
		apdu.flags |= SC_APDU_FLAGS_CHAINING;

	apdu.lc = inlen;
	apdu.data = (u8 *)in;
	apdu.datalen = inlen;
	apdu.le = ((outlen >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : outlen;
	apdu.resp = out;
	apdu.resplen = outlen;

	r = sc_transmit_apdu(card, &apdu);
	free(temp);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}


#ifdef ENABLE_OPENSSL
/**
 * Internal: update algorithm attribute for new key size (before generating key).
 **/
static int
pgp_update_new_algo_attr(sc_card_t *card, sc_cardctl_openpgp_keygen_info_t *key_info)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *algo_blob;
	unsigned int old_modulus_len;     /* measured in bits */
	unsigned int old_exponent_len;
	const unsigned int tag = 0x00C0 | key_info->keytype;
	u8 changed = 0;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);
	/* get old algorithm attributes */
	r = pgp_seek_blob(card, priv->mf, (0x00C0 | key_info->keytype), &algo_blob);
	LOG_TEST_RET(card->ctx, r, "Cannot get old algorithm attributes");
	old_modulus_len = bebytes2ushort(algo_blob->data + 1);  /* modulus length is coded in byte 2 & 3 */
	sc_log(card->ctx,
	       "Old modulus length %d, new %"SC_FORMAT_LEN_SIZE_T"u.",
	       old_modulus_len, key_info->modulus_len);
	old_exponent_len = bebytes2ushort(algo_blob->data + 3);  /* exponent length is coded in byte 3 & 4 */
	sc_log(card->ctx,
	       "Old exponent length %d, new %"SC_FORMAT_LEN_SIZE_T"u.",
	       old_exponent_len, key_info->exponent_len);

	/* Modulus */
	/* If passed modulus_len is zero, it means using old key size */
	if (key_info->modulus_len == 0) {
		sc_log(card->ctx, "Use old modulus length (%d).", old_modulus_len);
		key_info->modulus_len = old_modulus_len;
	}
	/* To generate key with new key size */
	else if (old_modulus_len != key_info->modulus_len) {
		algo_blob->data[1] = (unsigned char)(key_info->modulus_len >> 8);
		algo_blob->data[2] = (unsigned char)key_info->modulus_len;
		changed = 1;
	}

	/* Exponent */
	if (key_info->exponent_len == 0) {
		sc_log(card->ctx, "Use old exponent length (%d).", old_exponent_len);
		key_info->exponent_len = old_exponent_len;
	}
	else if (old_exponent_len != key_info->exponent_len) {
		algo_blob->data[3] = (unsigned char)(key_info->exponent_len >> 8);
		algo_blob->data[4] = (unsigned char)key_info->exponent_len;
		changed = 1;
	}

	/* If the key to-be-generated has different size,
	 * set this new value for GENERATE ASYMMETRIC KEY PAIR to work */
	if (changed) {
		r = pgp_put_data(card, tag, algo_blob->data, 6);
		/* Note: Don't use pgp_set_blob to set data, because it won't touch the real DO */
		LOG_TEST_RET(card->ctx, r, "Cannot set new algorithm attributes");
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: store creation time of key.
 * Pass non-zero outtime to use predefined time.
 * Pass zero/null outtime to calculate current time. outtime then will be output.
 * Pass null outtime to not receive output.
 **/
static int
pgp_store_creationtime(sc_card_t *card, u8 key_id, time_t *outtime)
{
	int r;
	time_t createtime = 0;
	const size_t timestrlen = 64;
	char timestring[65];
	u8 buf[4];

	LOG_FUNC_CALLED(card->ctx);
	if (key_id == 0 || key_id > 3) {
		sc_log(card->ctx, "Invalid key ID %d.", key_id);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
	}

	if (outtime != NULL && *outtime != 0)
		createtime = *outtime;
	else if (outtime != NULL)
		/* set output */
		*outtime = createtime = time(NULL);

	strftime(timestring, timestrlen, "%c %Z", gmtime(&createtime));
	sc_log(card->ctx, "Creation time %s.", timestring);
	/* Code borrowed from GnuPG */
	ulong2bebytes(buf, (unsigned long)createtime);
	r = pgp_put_data(card, 0x00CD + key_id, buf, 4);
	LOG_TEST_RET(card->ctx, r, "Cannot write to DO");
	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: calculate PGP fingerprints.
 * Reference: GnuPG, app-openpgp.c.
 * modulus and exponent are passed separately from key_info
 * because key_info->exponent may be null.
 **/
static int
pgp_calculate_and_store_fingerprint(sc_card_t *card, time_t ctime,
                                    u8* modulus, u8* exponent,
                                    sc_cardctl_openpgp_keygen_info_t *key_info)
{
	u8 fingerprint[SHA_DIGEST_LENGTH];
	size_t mlen = key_info->modulus_len >> 3;  /* 1/8 */
	size_t elen = key_info->exponent_len >> 3;  /* 1/8 */
	u8 *fp_buffer = NULL;  /* fingerprint buffer, not hashed */
	size_t fp_buffer_len;
	u8 *p; /* use this pointer to set fp_buffer content */
	size_t pk_packet_len;
	unsigned int tag;
	pgp_blob_t *fpseq_blob;
	u8 *newdata;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (modulus == NULL || exponent == NULL || mlen == 0 || elen == 0) {
		sc_log(card->ctx, "Null data (modulus or exponent)");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* http://tools.ietf.org/html/rfc4880  page 41, 72 */
	pk_packet_len =   1   /* version number */
	                + 4   /* creation time */
	                + 1   /* algorithm */
	                + 2   /* algorithm-specific fields: RSA modulus+exponent */
	                + mlen
	                + 2
	                + elen;

	fp_buffer_len = 3 + pk_packet_len;
	p = fp_buffer = calloc(fp_buffer_len, 1);
	if (!p) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_ENOUGH_MEMORY);
	}

	p[0] = 0x99;   /* http://tools.ietf.org/html/rfc4880  page 71 */
	ushort2bebytes(++p, (unsigned short)pk_packet_len);
	/* start pk_packet */
	p += 2;
	*p = 4;        /* Version 4 key */
	ulong2bebytes(++p, (unsigned long)ctime);    /* Creation time */
	p += 4;
	*p = 1;        /* RSA */
	/* algorithm-specific fields */
	ushort2bebytes(++p, (unsigned short)key_info->modulus_len);
	p += 2;
	memcpy(p, modulus, mlen);
	p += mlen;
	ushort2bebytes(++p, (unsigned short)key_info->exponent_len);
	p += 2;
	memcpy(p, exponent, elen);
	p = NULL;

	/* hash with SHA-1 */
	SHA1(fp_buffer, fp_buffer_len, fingerprint);
	free(fp_buffer);

	/* store to DO */
	tag = 0x00C6 + key_info->keytype;
	sc_log(card->ctx, "Write to DO %04X.", tag);
	r = pgp_put_data(card, 0x00C6 + key_info->keytype, fingerprint, SHA_DIGEST_LENGTH);
	LOG_TEST_RET(card->ctx, r, "Cannot write to DO.");

	/* update the blob containing fingerprints (00C5) */
	sc_log(card->ctx, "Update the blob containing fingerprints (00C5)");
	fpseq_blob = pgp_find_blob(card, 0x00C5);
	if (!fpseq_blob) {
		sc_log(card->ctx, "Not found 00C5");
		goto exit;
	}
	/* save the fingerprints sequence */
	newdata = malloc(fpseq_blob->len);
	if (!newdata) {
		sc_log(card->ctx, "Not enough memory to update fingerprints blob.");
		goto exit;
	}
	memcpy(newdata, fpseq_blob->data, fpseq_blob->len);
	/* move p to the portion holding the fingerprint of the current key */
	p = newdata + 20*(key_info->keytype - 1);
	/* copy new fingerprint value */
	memcpy(p, fingerprint, 20);
	/* set blob's data */
	pgp_set_blob(fpseq_blob, newdata, fpseq_blob->len);
	free(newdata);

exit:
	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: update pubkey blob.
 * Note that modulus_len, exponent_len is measured in bit.
 **/
static int
pgp_update_pubkey_blob(sc_card_t *card, u8* modulus, size_t modulus_len,
                       u8* exponent, size_t exponent_len, u8 key_id)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *pk_blob;
	unsigned int blob_id;
	sc_pkcs15_pubkey_t pubkey;
	u8 *data = NULL;
	size_t len;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (key_id == SC_OPENPGP_KEY_SIGN)
		blob_id = DO_SIGN_SYM;
	else if (key_id == SC_OPENPGP_KEY_ENCR)
		blob_id = DO_ENCR_SYM;
	else if (key_id == SC_OPENPGP_KEY_AUTH)
		blob_id = DO_AUTH_SYM;
	else {
		sc_log(card->ctx, "Unknown key id %X.", key_id);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	sc_log(card->ctx, "Get the blob %X.", blob_id);
	r = pgp_get_blob(card, priv->mf, blob_id, &pk_blob);
	LOG_TEST_RET(card->ctx, r, "Cannot get the blob.");

	/* encode pubkey */
	memset(&pubkey, 0, sizeof(pubkey));
	pubkey.algorithm = SC_ALGORITHM_RSA;
	pubkey.u.rsa.modulus.data  = modulus;
	pubkey.u.rsa.modulus.len   = modulus_len >> 3;  /* 1/8 */
	pubkey.u.rsa.exponent.data = exponent;
	pubkey.u.rsa.exponent.len  = exponent_len >> 3;

	r = sc_pkcs15_encode_pubkey(card->ctx, &pubkey, &data, &len);
	LOG_TEST_RET(card->ctx, r, "Cannot encode pubkey.");

	sc_log(card->ctx, "Update blob content.");
	r = pgp_set_blob(pk_blob, data, len);
	LOG_TEST_RET(card->ctx, r, "Cannot update blob content.");
	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: parse response data and set output
 **/
static int
pgp_parse_and_set_pubkey_output(sc_card_t *card, u8* data, size_t data_len,
                                sc_cardctl_openpgp_keygen_info_t *key_info)
{
	time_t ctime = 0;
	u8 *in = data;
	u8 *modulus = NULL;
	u8 *exponent = NULL;
	int r;
	LOG_FUNC_CALLED(card->ctx);

	/* store creation time */
	r = pgp_store_creationtime(card, key_info->keytype, &ctime);
	LOG_TEST_RET(card->ctx, r, "Cannot store creation time");

	/* parse response. Ref: pgp_enumerate_blob() */
	while (data_len > (size_t) (in - data)) {
		unsigned int cla, tag, tmptag;
		size_t		len;
		u8	*part = in;

		/* parse TLV structure */
		r = sc_asn1_read_tag((const u8**)&part,
							 data_len - (in - data),
							 &cla, &tag, &len);
		if (part == NULL)
			r = SC_ERROR_ASN1_OBJECT_NOT_FOUND;
		LOG_TEST_RET(card->ctx, r, "Unexpected end of contents.");
		/* undo ASN1's split of tag & class */
		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
			cla <<= 8;
		}
		tag |= cla;

		if (tag == 0x0081) {
			/* set the output data */
			if (key_info->modulus) {
				memcpy(key_info->modulus, part, len);
			}
			/* always set output for modulus_len */
			key_info->modulus_len = len*8;
			/* remember the modulus to calculate fingerprint later */
			modulus = part;
		}
		else if (tag == 0x0082) {
			/* set the output data */
			if (key_info->exponent) {
				memcpy(key_info->exponent, part, len);
			}
			/* always set output for exponent_len */
			key_info->exponent_len = len*8;
			/* remember the exponent to calculate fingerprint later */
			exponent = part;
		}

		/* go to next part to parse */
		/* This will be different from pgp_enumerate_blob() a bit */
		in = part + ((tag != 0x7F49) ? len : 0);
	}

	/* calculate and store fingerprint */
	sc_log(card->ctx, "Calculate and store fingerprint");
	r = pgp_calculate_and_store_fingerprint(card, ctime, modulus, exponent, key_info);
	LOG_TEST_RET(card->ctx, r, "Cannot store fingerprint.");
	/* update pubkey blobs (B601,B801, A401) */
	sc_log(card->ctx, "Update blobs holding pubkey info.");
	r = pgp_update_pubkey_blob(card, modulus, key_info->modulus_len,
	                           exponent, key_info->exponent_len, key_info->keytype);
	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: update card->algorithms
 */
static int
pgp_update_card_algorithms(sc_card_t *card, sc_cardctl_openpgp_keygen_info_t *key_info)
{
	sc_algorithm_info_t *algo;
	u8 id = key_info->keytype;

	LOG_FUNC_CALLED(card->ctx);

	if (id > card->algorithm_count) {
		sc_log(card->ctx,
		       "This key ID %u is out of the card's algorithm list.",
		       (unsigned int)id);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* get the algorithm corresponding to the key ID */
	algo = card->algorithms + (id - 1);
	/* update new key length attribute */
	algo->key_length = (unsigned int)key_info->modulus_len;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/**
 * ABI (card ctl): GENERATE ASYMMETRIC KEY PAIR
 * Set key_info->modulus_len to zero if want to use old key size.
 * Similarly for exponent length.
 * key_info->modulus_len and key_info->exponent_len will be returned with new values.
 **/
static int
pgp_gen_key(sc_card_t *card, sc_cardctl_openpgp_keygen_info_t *key_info)
{
	sc_apdu_t apdu;
	/* temporary variables to hold APDU params */
	u8 apdu_case;
	u8 *apdu_data;
	size_t apdu_le;
	size_t resplen = 0;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	/* FIXME the compilers don't assure that the buffers set here as
	 * apdu_data are present until the end of the function */
	/* set Control Reference Template for key */
	if (key_info->keytype == SC_OPENPGP_KEY_SIGN)
		apdu_data = (unsigned char *) "\xb6";
		/* as a string, apdu_data will end with '\0' (B6 00) */
	else if (key_info->keytype == SC_OPENPGP_KEY_ENCR)
		apdu_data = (unsigned char *) "\xb8";
	else if (key_info->keytype == SC_OPENPGP_KEY_AUTH)
		apdu_data = (unsigned char *) "\xa4";
	else {
		sc_log(card->ctx, "Unknown key type %X.", key_info->keytype);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (card->type == SC_CARD_TYPE_OPENPGP_GNUK && key_info->modulus_len != 2048) {
		sc_log(card->ctx, "Gnuk does not support other key length than 2048.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* set attributes for new-generated key */
	r = pgp_update_new_algo_attr(card, key_info);
	LOG_TEST_RET(card->ctx, r, "Cannot set attributes for new-generated key");

	/* Test whether we will need extended APDU. 1900 is an
	 * arbitrary modulus length which for sure fits into a short APDU.
	 * This idea is borrowed from GnuPG code.  */
	if (card->caps & SC_CARD_CAP_APDU_EXT
		&& key_info->modulus_len > 1900
		&& card->type != SC_CARD_TYPE_OPENPGP_GNUK) {
		/* We won't store to apdu variable yet, because it will be reset in
		 * sc_format_apdu() */
		apdu_le = card->max_recv_size;
		apdu_case = SC_APDU_CASE_4_EXT;
	}
	else {
		apdu_case = SC_APDU_CASE_4_SHORT;
		apdu_le = 256;
		resplen = MAXLEN_RESP_PUBKEY;
	}
	if (card->type == SC_CARD_TYPE_OPENPGP_GNUK) {
		resplen = MAXLEN_RESP_PUBKEY_GNUK;
	}

	/* prepare APDU */
	sc_format_apdu(card, &apdu, apdu_case, 0x47, 0x80, 0);
	apdu.data = apdu_data;
	apdu.datalen = 2;  /* Data = B600 */
	apdu.lc = 2;
	apdu.le = apdu_le;

	/* buffer to receive response */
	apdu.resplen = (resplen > 0) ? resplen : apdu_le;
	apdu.resp = calloc(apdu.resplen, 1);
	if (apdu.resp == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_ENOUGH_MEMORY);
	}

	/* send */
	sc_log(card->ctx, "Waiting for the card to generate key...");
	r = sc_transmit_apdu(card, &apdu);
	sc_log(card->ctx, "Card has done key generation.");
	if (r < 0) {
		sc_log(card->ctx, "APDU transmit failed. Error %s.", sc_strerror(r));
		goto finish;
	}

	/* check response */
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	/* instruct more in case of error */
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Please verify PIN first.");
		goto finish;
	}

	/* parse response data and set output */
	pgp_parse_and_set_pubkey_output(card, apdu.resp, apdu.resplen, key_info);
	pgp_update_card_algorithms(card, key_info);

finish:
	free(apdu.resp);
	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * Internal: build TLV.
 *
 * FIXME use `sc_asn1_put_tag` or similar instead
 *
 * @param[in]  data   The data ("value") part to build TLV.
 * @param[in]  len    Data length
 * @param[out] out    The buffer of overall TLV. This buffer should be freed later.
 * @param[out] outlen The length of buffer out.
 **/
static int
pgp_build_tlv(sc_context_t *ctx, unsigned int tag, u8 *data, size_t len, u8 **out, size_t *outlen)
{
	u8 highest_order = 0;
	int r;

	r = sc_asn1_write_element(ctx, tag, data, len, out, outlen);
	LOG_TEST_RET(ctx, r, "Failed to write ASN.1 element");

	/* Restore class bits stripped by sc_asn1_write_element */
	/* determine the leftmost byte of tag, which contains class bits */
	while ((tag >> 8*highest_order) != 0) {
		highest_order++;
	}
	highest_order--;

	/* restore class bits in output */
	if (highest_order < 4)
		*out[0] |= (tag >> 8*highest_order);

	return SC_SUCCESS;
}


/**
 * Internal: set Tag & Length components for TLV, store them in buffer.
 *
 * FIXME use `sc_asn1_put_tag` or similar instead
 *
 * Return the total length of Tag + Length.
 * Note that the Value components is not counted.
 * Ref: add_tlv() of GnuPG code.
 **/
static size_t
set_taglength_tlv(u8 *buffer, unsigned int tag, size_t length)
{
	u8 *p = buffer;

	assert(tag <= 0xffff);
	if (tag > 0xff)
		*p++ = (tag >> 8) & 0xFF;
	*p++ = tag;
	if (length < 128)
		*p++ = (u8)length;
	else if (length < 256) {
		*p++ = 0x81;
		*p++ = (u8)length;
	}
	else {
		if (length > 0xffff)
			length = 0xffff;
		*p++ = 0x82;
		*p++ = (length >> 8) & 0xFF;
		*p++ = length & 0xFF;
	}

	return p - buffer;
}


/**
 * Internal: build Extended Header list (sec 4.3.3.7 - OpenPGP card spec v.2)
 **/
static int
pgp_build_extended_header_list(sc_card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info,
                               u8 **result, size_t *resultlen)
{
	sc_context_t *ctx = card->ctx;
	/* Cardholder private key template (7F48) part */
	const size_t max_prtem_len = 7*(1 + 3);     /* 7 components */
	                                            /* 1 for tag name (91, 92... 97)
	                                             * 3 for storing length */
	u8 pritemplate[7*(1 + 3)];
	size_t tpl_len = 0;     /* Actual size of pritemplate */
	/* Concatenation of key data */
	u8 kdata[3 + 256 + 256 + 512];  /* Exponent is stored in 3 bytes
	                                 * With maximum 4096-bit key,
	                                 * p and q can be stored in 256 bytes (2048 bits).
	                                 * Maximum 4096-bit modulus is stored in 512 bytes */
	size_t kdata_len = 0;   /* Actual size of kdata */
	u8 *tlvblock = NULL;
	size_t tlvlen = 0;
	u8 *tlv_5f48 = NULL;
	size_t tlvlen_5f48 = 0;
	u8 *tlv_7f48 = NULL;
	size_t tlvlen_7f48 = 0;
	u8 *data = NULL;
	size_t len = 0;
	u8 *p = NULL;
	u8 *components[] = {key_info->e, key_info->p, key_info->q, key_info->n};
	size_t componentlens[] = {key_info->e_len, key_info->p_len, key_info->q_len, key_info->n_len};
	unsigned int componenttags[] = {0x91, 0x92, 0x93, 0x97};
	char *componentnames[] = {
		"public exponent",
		"prime p",
		"prime q",
		"modulus"
	};
	size_t comp_to_add = 3;
	size_t req_e_len = 0;     /* The exponent length specified in Algorithm Attributes */
	pgp_blob_t *alat_blob;
	u8 i;
	int r;

	LOG_FUNC_CALLED(ctx);

	if (key_info->keyformat == SC_OPENPGP_KEYFORMAT_STDN
		|| key_info->keyformat == SC_OPENPGP_KEYFORMAT_CRTN)
		comp_to_add = 4;

	/* validate */
	if (comp_to_add == 4 && (key_info->n == NULL || key_info->n_len == 0)){
		sc_log(ctx, "Error: Modulus required!");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Cardholder private key template's data part */
	memset(pritemplate, 0, max_prtem_len);

	/* get required exponent length */
	alat_blob = pgp_find_blob(card, 0x00C0 | key_info->keytype);
	if (!alat_blob) {
		sc_log(ctx, "Cannot read Algorithm Attributes.");
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}
	req_e_len = bebytes2ushort(alat_blob->data + 3) >> 3;   /* 1/8 */
	assert(key_info->e_len <= req_e_len);

	/* We need to right justify the exponent with required length,
	 * e.g. from '01 00 01' to '00 01 00 01' */
	if (key_info->e_len < req_e_len) {
		/* create new buffer */
		p = calloc(req_e_len, 1);
		if (!p)
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_ENOUGH_MEMORY);
		memcpy(p + req_e_len - key_info->e_len, key_info->e, key_info->e_len);
		key_info->e_len = req_e_len;
		/* set key_info->e to new buffer */
		free(key_info->e);
		key_info->e = p;
		components[0] = p;
		componentlens[0] = req_e_len;
	}

	/* start from beginning of pritemplate */
	p = pritemplate;

	for (i = 0; i < comp_to_add; i++) {
		sc_log(ctx, "Set Tag+Length for %s (%X).", componentnames[i], componenttags[i]);
		len = set_taglength_tlv(p, componenttags[i], componentlens[i]);
		tpl_len += len;

		/*
		 *       <-- kdata_len --><--  Copy here  -->
		 * kdata |===============|___________________
		 */
		memcpy(kdata + kdata_len, components[i], componentlens[i]);
		kdata_len += componentlens[i];

		/* Move p to next part and build */
		p += len;
	}

	/* TODO: Components for CRT format */

	/* TLV block for 7F48 */
	r = pgp_build_tlv(ctx, 0x7F48, pritemplate, tpl_len, &tlv_7f48, &tlvlen_7f48);
	LOG_TEST_RET(ctx, r, "Failed to build TLV for 7F48.");
	tlv_7f48[0] |= 0x7F;
	r = pgp_build_tlv(ctx, 0x5f48, kdata, kdata_len, &tlv_5f48, &tlvlen_5f48);
	if (r < 0) {
		sc_log(ctx, "Failed to build TLV for 5F48.");
		goto out;
	}

	/* data part's length for Extended Header list */
	len = 2 + tlvlen_7f48 + tlvlen_5f48;
	/* set data part content */
	data = calloc(len, 1);
	if (data == NULL) {
		sc_log(ctx, "Not enough memory.");
		r = SC_ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}
	switch (key_info->keytype) {
	case SC_OPENPGP_KEY_SIGN:
		data[0] = 0xB6;
		break;
	case SC_OPENPGP_KEY_ENCR:
		data[0] = 0xB8;
		break;
	case SC_OPENPGP_KEY_AUTH:
		data[0] = 0xA4;
		break;
	default:
		sc_log(ctx, "Unknown key type %d.", key_info->keytype);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto out;
	}
	memcpy(data + 2, tlv_7f48, tlvlen_7f48);
	memcpy(data + 2 + tlvlen_7f48, tlv_5f48, tlvlen_5f48);
	r = pgp_build_tlv(ctx, 0x4D, data, len, &tlvblock, &tlvlen);
	if (r < 0) {
		sc_log(ctx, "Cannot build TLV for Extended Header list.");
		goto out;
	}
	/* set output */
	if (result != NULL) {
		*result = tlvblock;
		*resultlen = tlvlen;
	} else {
		free(tlvblock);
	}

out:
	free(data);
	free(tlv_5f48);
	free(tlv_7f48);
	LOG_FUNC_RETURN(ctx, r);
}


/**
 * ABI (card ctl): store key
 **/
static int
pgp_store_key(sc_card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info)
{
	sc_context_t *ctx = card->ctx;
	sc_cardctl_openpgp_keygen_info_t pubkey;
	u8 *data = NULL;
	size_t len = 0;
	int r;

	LOG_FUNC_CALLED(ctx);

	/* Validate */
	if (key_info->keytype < 1 || key_info->keytype > 3) {
		sc_log(ctx, "Unknown key type %d.", key_info->keytype);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	/* we just support standard key format */
	switch (key_info->keyformat) {
	case SC_OPENPGP_KEYFORMAT_STD:
	case SC_OPENPGP_KEYFORMAT_STDN:
		break;

	case SC_OPENPGP_KEYFORMAT_CRT:
	case SC_OPENPGP_KEYFORMAT_CRTN:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* we only support exponent of maximum 32 bits */
	if (key_info->e_len > 4) {
		sc_log(card->ctx,
		       "Exponent %"SC_FORMAT_LEN_SIZE_T"u-bit (>32) is not supported.",
		       key_info->e_len * 8);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	/* set algorithm attributes */
	memset(&pubkey, 0, sizeof(pubkey));
	pubkey.keytype = key_info->keytype;
	if (key_info->n && key_info->n_len) {
		pubkey.modulus = key_info->n;
		pubkey.modulus_len = 8*key_info->n_len;
		/* We won't update exponent length, because smaller exponent length
		 * will be padded later */
	}
	r = pgp_update_new_algo_attr(card, &pubkey);
	LOG_TEST_RET(card->ctx, r, "Failed to update new algorithm attributes");
	/* build Extended Header list */
	r = pgp_build_extended_header_list(card, key_info, &data, &len);
	if (r < 0) {
		sc_log(ctx, "Failed to build Extended Header list.");
		goto out;
	}
	/* write to DO */
	r = pgp_put_data(card, 0x4D, data, len);
	if (r < 0) {
		sc_log(ctx, "Failed to write to DO.");
		goto out;
	}

	free(data);
	data = NULL;

	/* store creation time */
	r = pgp_store_creationtime(card, key_info->keytype, &key_info->creationtime);
	LOG_TEST_RET(card->ctx, r, "Cannot store creation time");

	/* Calculate and store fingerprint */
	sc_log(card->ctx, "Calculate and store fingerprint");
	r = pgp_calculate_and_store_fingerprint(card, key_info->creationtime, key_info->n, key_info->e, &pubkey);
	LOG_TEST_RET(card->ctx, r, "Cannot store fingerprint.");
	/* update pubkey blobs (B601,B801, A401) */
	sc_log(card->ctx, "Update blobs holding pubkey info.");
	r = pgp_update_pubkey_blob(card, key_info->n, 8*key_info->n_len,
	                           key_info->e, 8*key_info->e_len, key_info->keytype);

	sc_log(ctx, "Update card algorithms.");
	pgp_update_card_algorithms(card, &pubkey);

out:
	if (data) {
		free(data);
		data = NULL;
	}
	LOG_FUNC_RETURN(ctx, r);
}

#endif /* ENABLE_OPENSSL */


/**
 * ABI (card ctl): erase card
 **/
static int
pgp_erase_card(sc_card_t *card)
{
	/* Special series of commands to erase OpenPGP card,
	 * according to https://www.crypto-stick.com/en/faq
	 * (How to reset a Crypto Stick? question).
	 * Gnuk is known not to support this feature. */
	const char *apdu_hex[] = {
		/* block PIN1 */
		"00:20:00:81:08:40:40:40:40:40:40:40:40",
		"00:20:00:81:08:40:40:40:40:40:40:40:40",
		"00:20:00:81:08:40:40:40:40:40:40:40:40",
		"00:20:00:81:08:40:40:40:40:40:40:40:40",
		/* block PIN3 */
		"00:20:00:83:08:40:40:40:40:40:40:40:40",
		"00:20:00:83:08:40:40:40:40:40:40:40:40",
		"00:20:00:83:08:40:40:40:40:40:40:40:40",
		"00:20:00:83:08:40:40:40:40:40:40:40:40",
		/* TERMINATE */
		"00:e6:00:00",
		NULL
	};
	sc_apdu_t apdu;
	int i;
	int r = SC_SUCCESS;
	struct pgp_priv_data *priv = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (priv->bcd_version < OPENPGP_CARD_2_0
			|| priv->state == CARD_STATE_UNKNOWN) {
		LOG_TEST_RET(card->ctx, SC_ERROR_NO_CARD_SUPPORT,
				"Card does not offer life cycle management");
	}

	switch (priv->state) {
		case CARD_STATE_ACTIVATED:
			/* iterate over the commands above */
			for (i = 0; apdu_hex[i] != NULL; i++) {
				u8 apdu_bin[25];	/* large enough to convert apdu_hex */
				size_t apdu_bin_len = sizeof(apdu_bin);
				u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

				/* convert hex array to bin array */
				r = sc_hex_to_bin(apdu_hex[i], apdu_bin, &apdu_bin_len);
				LOG_TEST_RET(card->ctx, r, "Failed to convert APDU bytes");

				/* build APDU from binary array */
				r = sc_bytes2apdu(card->ctx, apdu_bin, apdu_bin_len, &apdu);
				if (r) {
					sc_log(card->ctx, "Failed to build APDU");
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
				}

				apdu.resp = rbuf;
				apdu.resplen = sizeof(rbuf);

				/* send APDU to card */
				sc_log(card->ctx, "Sending APDU%d %s", i, apdu_hex[i]);
				r = sc_transmit_apdu(card, &apdu);
				LOG_TEST_RET(card->ctx, r, "Transmitting APDU failed");
			}
			/* fall through */
		case CARD_STATE_INITIALIZATION:
			sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x44, 0, 0);
			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(card->ctx, r, "Transmitting APDU failed");
			break;
		default:
			LOG_TEST_RET(card->ctx, SC_ERROR_NO_CARD_SUPPORT,
					"Card does not offer life cycle management");
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * ABI: card ctl: perform special card-specific operations.
 */
static int
pgp_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);

	switch(cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		memmove((sc_serial_number_t *) ptr, &card->serialnr, sizeof(card->serialnr));
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		break;

#ifdef ENABLE_OPENSSL
	case SC_CARDCTL_OPENPGP_GENERATE_KEY:
		r = pgp_gen_key(card, (sc_cardctl_openpgp_keygen_info_t *) ptr);
		LOG_FUNC_RETURN(card->ctx, r);
		break;

	case SC_CARDCTL_OPENPGP_STORE_KEY:
		r = pgp_store_key(card, (sc_cardctl_openpgp_keystore_info_t *) ptr);
		LOG_FUNC_RETURN(card->ctx, r);
		break;
#endif /* ENABLE_OPENSSL */
	case SC_CARDCTL_ERASE_CARD:
		r = pgp_erase_card(card);
		LOG_FUNC_RETURN(card->ctx, r);
		break;
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}


/**
 * Internal: delete key.
 */
static int
gnuk_delete_key(sc_card_t *card, u8 key_id)
{
	sc_context_t *ctx = card->ctx;
	int r = SC_SUCCESS;
	char *data = NULL;

	LOG_FUNC_CALLED(ctx);

	if (key_id < 1 || key_id > 3) {
		sc_log(ctx, "Key ID %d is invalid. Should be 1, 2 or 3.", key_id);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* delete fingerprint */
	sc_log(ctx, "Delete fingerprints");
	r = pgp_put_data(card, 0xC6 + key_id, NULL, 0);
	LOG_TEST_RET(ctx, r, "Failed to delete fingerprints");
	/* delete creation time */
	sc_log(ctx, "Delete creation time");
	r = pgp_put_data(card, 0xCD + key_id, NULL, 0);
	LOG_TEST_RET(ctx, r, "Failed to delete creation time");

	/* rewrite Extended Header List */
	sc_log(ctx, "Rewrite Extended Header List");

	if (key_id == 1)
		data = "\x4D\x02\xB6";
	else if (key_id == 2)
		data = "\x4D\x02\xB8";
	else if (key_id == 3)
		data = "\x4D\x02\xA4";

	r = pgp_put_data(card, 0x4D, (const u8 *)data, strlen((const char *)data) + 1);

	LOG_FUNC_RETURN(ctx, r);
}


/**
 * ABI: DELETE FILE.
 */
static int
pgp_delete_file(sc_card_t *card, const sc_path_t *path)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *blob;
	sc_file_t *file;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* sc_pkcs15init_delete_by_path() sets the path type to SC_PATH_TYPE_FILE_ID */
	r = pgp_select_file(card, path, &file);
	LOG_TEST_RET(card->ctx, r, "Cannot select file.");

	/* save "current" blob */
	blob = priv->current;

	/* do try to delete MF */
	if (blob == priv->mf)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (card->type != SC_CARD_TYPE_OPENPGP_GNUK &&
		(file->id == DO_SIGN_SYM || file->id == DO_ENCR_SYM || file->id == DO_AUTH_SYM)) {
		/* These tags are just symbolic. We don't really delete them. */
		r = SC_SUCCESS;
	}
	else if (card->type == SC_CARD_TYPE_OPENPGP_GNUK && file->id == DO_SIGN_SYM) {
		r = gnuk_delete_key(card, 1);
	}
	else if (card->type == SC_CARD_TYPE_OPENPGP_GNUK && file->id == DO_ENCR_SYM) {
		r = gnuk_delete_key(card, 2);
	}
	else if (card->type == SC_CARD_TYPE_OPENPGP_GNUK && file->id == DO_AUTH_SYM) {
		r = gnuk_delete_key(card, 3);
	}
	else {
		/* call pgp_put_data() with zero-sized NULL-buffer to zap the DO contents */
		r = pgp_put_data(card, file->id, NULL, 0);
	}

	/* set "current" blob to parent */
	priv->current = blob->parent;

	LOG_FUNC_RETURN(card->ctx, r);
}


/**
 * ABI: UPDATE BINARY.
 */
static int
pgp_update_binary(sc_card_t *card, unsigned int idx,
		  const u8 *buf, size_t count, unsigned long flags)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	pgp_blob_t *blob = priv->current;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	/* We will use PUT DATA to write to DO.
	 * As PUT DATA does not support idx, we don't either */
	if (idx > 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	/* When a dummy file, e.g "11001101", is selected, the current blob
	 * is set to NULL. We don't really put data to dummy file. */
	if (blob != NULL) {
		r = pgp_put_data(card, blob->id, buf, count);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


static int pgp_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	struct pgp_priv_data *priv = DRVDATA(card); /* may be null during initialization */
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (card->flags & SC_CARD_FLAG_KEEP_ALIVE
			&& was_reset <= 0
			&& priv != NULL && priv->mf && priv->mf->file) {
		/* check whether applet is still selected */
		unsigned char aid[16];

		r = sc_get_data(card, 0x004F, aid, sizeof aid);
		if ((size_t) r != priv->mf->file->namelen
				|| 0 != memcmp(aid, priv->mf->file->name, r)) {
			/* reselect is required */
			was_reset = 1;
		}
		r = SC_SUCCESS;
	}

	if (was_reset > 0) {
		sc_file_t	*file = NULL;
		sc_path_t	path;
		/* select application "OpenPGP" */
		sc_format_path("D276:0001:2401", &path);
		path.type = SC_PATH_TYPE_DF_NAME;
		r = iso_ops->select_file(card, &path, &file);
		sc_file_free(file);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


struct sc_card_driver *
sc_get_openpgp_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;

	pgp_ops = *iso_ops;
	pgp_ops.match_card	= pgp_match_card;
	pgp_ops.init		= pgp_init;
	pgp_ops.finish		= pgp_finish;
	pgp_ops.select_file	= pgp_select_file;
	pgp_ops.list_files	= pgp_list_files;
	pgp_ops.get_challenge	= pgp_get_challenge;
	pgp_ops.read_binary	= pgp_read_binary;
	pgp_ops.write_binary	= pgp_write_binary;
	pgp_ops.pin_cmd		= pgp_pin_cmd;
	pgp_ops.logout		= pgp_logout;
	pgp_ops.get_data	= pgp_get_data;
	pgp_ops.put_data	= pgp_put_data;
	pgp_ops.set_security_env= pgp_set_security_env;
	pgp_ops.compute_signature= pgp_compute_signature;
	pgp_ops.decipher	= pgp_decipher;
	pgp_ops.card_ctl	= pgp_card_ctl;
	pgp_ops.delete_file	= pgp_delete_file;
	pgp_ops.update_binary	= pgp_update_binary;
	pgp_ops.card_reader_lock_obtained = pgp_card_reader_lock_obtained;

	return &pgp_drv;
}
