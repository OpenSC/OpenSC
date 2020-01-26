/*
 * card-openpgp.h: Support for OpenPGP card
 *
 * Copyright (C) 2020  Peter Marschall <peter@adpm.de>
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

#ifndef _CARD_OPENPGP_H
#define _CARD_OPENPGP_H

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

typedef enum _pgp_do_type {		/* DO type */
	SIMPLE		= SC_FILE_TYPE_WORKING_EF,
	CONSTRUCTED	= SC_FILE_TYPE_DF
} pgp_do_type_t;

typedef enum _pgp_version {		/* 2-byte BCD-alike encoded version number */
	OPENPGP_CARD_1_0	= 0x0100,
	OPENPGP_CARD_1_1	= 0x0101,
	OPENPGP_CARD_2_0	= 0x0200,
	OPENPGP_CARD_2_1	= 0x0201,
	OPENPGP_CARD_2_2	= 0x0202,
	OPENPGP_CARD_3_0	= 0x0300,
	OPENPGP_CARD_3_1	= 0x0301,
	OPENPGP_CARD_3_2	= 0x0302,
	OPENPGP_CARD_3_3	= 0x0303,
	OPENPGP_CARD_3_4	= 0x0304,
} pgp_version_t;

typedef enum _pgp_access {		/* access flags for the respective DO/file */
	READ_NEVER	= 0x0010,
	READ_PIN1	= 0x0011,
	READ_PIN2	= 0x0012,
	READ_PIN3	= 0x0014,
	READ_ALWAYS	= 0x0018,
	READ_MASK	= 0x00FF,
	WRITE_NEVER	= 0x1000,
	WRITE_PIN1	= 0x1100,
	WRITE_PIN2	= 0x1200,
	WRITE_PIN3	= 0x1400,
	WRITE_ALWAYS	= 0x1800,
	WRITE_MASK	= 0x1F00
} pgp_access_t;

typedef enum _pgp_ext_caps {	/* extended capabilities/features: bit flags */
	EXT_CAP_ALG_ATTR_CHANGEABLE	= 0x0004,
	EXT_CAP_PRIVATE_DO		= 0x0008,
	EXT_CAP_C4_CHANGEABLE		= 0x0010,
	EXT_CAP_KEY_IMPORT		= 0x0020,
	EXT_CAP_GET_CHALLENGE		= 0x0040,
	EXT_CAP_SM			= 0x0080,
	EXT_CAP_LCS			= 0x0100,
	EXT_CAP_CHAINING		= 0x1000,
	EXT_CAP_APDU_EXT		= 0x2000,
	EXT_CAP_MSE			= 0x4000
} pgp_ext_caps_t;

typedef enum _pgp_card_state {
	CARD_STATE_UNKNOWN		= 0x00,
	CARD_STATE_INITIALIZATION	= 0x03,
	CARD_STATE_ACTIVATED		= 0x05
} pgp_card_state_t;

typedef enum _pgp_sm_algo {
	SM_ALGO_NONE	= 0,	/* SM not supported */
	SM_ALGO_AES128	= 1,
	SM_ALGO_AES256	= 2,
	SM_ALGO_SCP11b	= 3,
	SM_ALGO_3DES	= 256,	/* 2.x: coded as 0 in DO C0 */
	SM_ALGO_UNKNOWN	= 257	/* 3.x: coded as 0 in DO C0 */
} pgp_sm_algo_t;

typedef struct _pgp_do_info {
	unsigned int	id;		/* ID of the DO in question */

	pgp_do_type_t	type;		/* constructed DO or not */
	pgp_access_t	access;		/* R/W access levels for the DO */

	/* function to get the DO from the card:
	 * only != NULL is DO if readable and not only a part of a constructed DO */
	int		(*get_fn)(sc_card_t *, unsigned int, u8 *, size_t);
	/* function to write the DO to the card:
	 * only != NULL if DO is writeable under some conditions */
	int		(*put_fn)(sc_card_t *, unsigned int, const u8 *, size_t);
} pgp_do_info_t;

typedef struct pgp_blob {
	struct pgp_blob	*next;		/* pointer to next sibling */
	struct pgp_blob	*parent;	/* pointer to parent */
	pgp_do_info_t	*info;

	sc_file_t	*file;
	unsigned int	id;
	int		status;

	unsigned char	*data;
	unsigned int	len;
	struct pgp_blob *files;		/* pointer to 1st child */
} pgp_blob_t;


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

/* Maximal size of a DO:
 * v2.0+: max. certificate size it at bytes 5-6 of Extended Capabilities DO 00C0
 * v3.0+: max. special DO size is at bytes 7-8 of Extended Capabilities DO 00C0
 * Theoretically we should have the 64k, but we currently limit to 8k. */
#define	MAX_OPENPGP_DO_SIZE	8192


typedef struct _pgp_ec_curves {
	struct sc_object_id oid;
	size_t size;
	struct sc_object_id oid_binary;
} pgp_ec_curves_t;


#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))

struct pgp_priv_data {
	pgp_blob_t		*mf;
	pgp_blob_t		*current;	/* currently selected file */

	pgp_version_t		bcd_version;
	pgp_do_info_t		*pgp_objects;

	pgp_card_state_t	state;		/* card state */
	pgp_ext_caps_t		ext_caps;	/* extended capabilities */

	pgp_sm_algo_t		sm_algo;	/* Secure Messaging algorithm */

	size_t			max_challenge_size;
	size_t			max_cert_size;
	size_t			max_specialDO_size;

	sc_security_env_t	sec_env;
};

#define BCD2UCHAR(x) (((((x) & 0xF0) >> 4) * 10) + ((x) & 0x0F))

#endif
