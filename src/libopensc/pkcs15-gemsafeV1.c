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

/* Initially written by David Mattes <david.mattes@boeing.com> */
/* Support for multiple key containers by Lukas Wunner <lukas@wunner.de> */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"

#define MANU_ID			"Gemplus"
#define APPLET_NAME		"GemSAFE V1"
#define DRIVER_SERIAL_NUMBER	"v0.9"
#define GEMSAFE_APP_PATH	"3F001600"
#define GEMSAFE_PATH		"3F0016000004"

/* Apparently, the Applet max read "quanta" is 248 bytes
 * Gemalto ClassicClient reads files in chunks of 238 bytes
 */
#define GEMSAFE_READ_QUANTUM    248
#define GEMSAFE_MAX_OBJLEN      28672

static int
sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
	int type, int authority,
	const sc_path_t *path,
	const sc_pkcs15_id_t *id,
	const char *label, int obj_flags);

static int
sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_id_t *id, const char *label,
	const sc_path_t *path, int ref, int type,
	unsigned int min_length,
	unsigned int max_length,
	int flags, int tries_left, const char pad_char, int obj_flags);

static int
sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_id_t *id,
	const char *label,
	int type, unsigned int modulus_length, int usage,
	const sc_path_t *path, int ref,
	const sc_pkcs15_id_t *auth_id, int obj_flags);

typedef struct cdata_st {
	char	   *label;
	int	    authority;
	const char *path;
	size_t	    index;
	size_t	    count;
	const char *id;
	int         obj_flags;
} cdata;

const unsigned int gemsafe_cert_max = 12;

cdata gemsafe_cert[] = {
	{"DS certificate #1",  0, GEMSAFE_PATH, 0, 0, "45", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #2",  0, GEMSAFE_PATH, 0, 0, "46", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #3",  0, GEMSAFE_PATH, 0, 0, "47", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #4",  0, GEMSAFE_PATH, 0, 0, "48", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #5",  0, GEMSAFE_PATH, 0, 0, "49", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #6",  0, GEMSAFE_PATH, 0, 0, "50", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #7",  0, GEMSAFE_PATH, 0, 0, "51", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #8",  0, GEMSAFE_PATH, 0, 0, "52", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #9",  0, GEMSAFE_PATH, 0, 0, "53", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #10", 0, GEMSAFE_PATH, 0, 0, "54", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #11", 0, GEMSAFE_PATH, 0, 0, "55", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"DS certificate #12", 0, GEMSAFE_PATH, 0, 0, "56", SC_PKCS15_CO_FLAG_MODIFIABLE},
};

typedef struct pdata_st {
	const u8    atr[SC_MAX_ATR_SIZE];
	const size_t atr_len;
	const char *id;
	const char *label;
	const char *path;
	const int   ref;
	const int   type;
	const unsigned int maxlen;
	const unsigned int minlen;
	const int   flags;
	const int   tries_left;
	const char  pad_char;
	const int   obj_flags;
} pindata;

const unsigned int gemsafe_pin_max = 2;

const pindata gemsafe_pin[] = {
	/* ATR-specific PIN policies, first match found is used: */
	{ {0x3B, 0x7D, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65,
	   0xB0, 0x83, 0x11, 0x48, 0xC8, 0x83, 0x00, 0x90, 0x00}, 18,
	  "01", "DS pin", GEMSAFE_PATH, 0x01, SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
	  8, 4, SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_LOCAL,
	  3, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE },
	/* default PIN policy comes last: */
	{ { 0 }, 0,
	  "01", "DS pin", GEMSAFE_PATH, 0x01, SC_PKCS15_PIN_TYPE_BCD,
	  16, 6, SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_LOCAL,
	  3, 0xFF, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE }
};

typedef struct prdata_st {
	const char *id;
	char	   *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} prdata;

#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN

prdata gemsafe_prkeys[] = {
	{ "45", "DS key #1",  1024, USAGE_AUT, GEMSAFE_PATH, 0x03, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "46", "DS key #2",  1024, USAGE_AUT, GEMSAFE_PATH, 0x04, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "47", "DS key #3",  1024, USAGE_AUT, GEMSAFE_PATH, 0x05, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "48", "DS key #4",  1024, USAGE_AUT, GEMSAFE_PATH, 0x06, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "49", "DS key #5",  1024, USAGE_AUT, GEMSAFE_PATH, 0x07, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "50", "DS key #6",  1024, USAGE_AUT, GEMSAFE_PATH, 0x08, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "51", "DS key #7",  1024, USAGE_AUT, GEMSAFE_PATH, 0x09, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "52", "DS key #8",  1024, USAGE_AUT, GEMSAFE_PATH, 0x0a, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "53", "DS key #9",  1024, USAGE_AUT, GEMSAFE_PATH, 0x0b, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "54", "DS key #10", 1024, USAGE_AUT, GEMSAFE_PATH, 0x0c, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "55", "DS key #11", 1024, USAGE_AUT, GEMSAFE_PATH, 0x0d, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "56", "DS key #12", 1024, USAGE_AUT, GEMSAFE_PATH, 0x0e, "01", SC_PKCS15_CO_FLAG_PRIVATE},
};

static int gemsafe_get_cert_len(sc_card_t *card)
{
	int r;
	u8  ibuf[GEMSAFE_MAX_OBJLEN];
	u8 *iptr;
	struct sc_path path;
	struct sc_file *file;
	size_t objlen, certlen;
	unsigned int ind, i=0;

	sc_format_path(GEMSAFE_PATH, &path);
	r = sc_select_file(card, &path, &file);
	if (r != SC_SUCCESS || !file)
		return SC_ERROR_INTERNAL;

	/* Initial read */
	r = sc_read_binary(card, 0, ibuf, GEMSAFE_READ_QUANTUM, 0);
	if (r < 0)
		return SC_ERROR_INTERNAL;

	/* Actual stored object size is encoded in first 2 bytes
	 * (allocated EF space is much greater!)
	 */
	objlen = (((size_t) ibuf[0]) << 8) | ibuf[1];
	sc_log(card->ctx, "Stored object is of size: %"SC_FORMAT_LEN_SIZE_T"u",
	       objlen);
	if (objlen < 1 || objlen > GEMSAFE_MAX_OBJLEN) {
	    sc_log(card->ctx, "Invalid object size: %"SC_FORMAT_LEN_SIZE_T"u",
		   objlen);
	    return SC_ERROR_INTERNAL;
	}

	/* It looks like the first thing in the block is a table of
	 * which keys are allocated. The table is small and is in the
	 * first 248 bytes. Example for a card with 10 key containers:
	 * 01 f0 00 03 03 b0 00 03     <=  1st key unallocated
	 * 01 f0 00 04 03 b0 00 04     <=  2nd key unallocated
	 * 01 fe 14 00 05 03 b0 00 05  <=  3rd key allocated
	 * 01 fe 14 01 06 03 b0 00 06  <=  4th key allocated
	 * 01 f0 00 07 03 b0 00 07     <=  5th key unallocated
	 * ...
	 * 01 f0 00 0c 03 b0 00 0c     <= 10th key unallocated
	 * For allocated keys, the fourth byte seems to indicate the
	 * default key and the fifth byte indicates the key_ref of
	 * the private key.
	 */
	ind = 2; /* skip length */
	while (ibuf[ind] == 0x01 && i < gemsafe_cert_max) {
		if (ibuf[ind+1] == 0xFE) {
			gemsafe_prkeys[i].ref = ibuf[ind+4];
			sc_log(card->ctx, "Key container %d is allocated and uses key_ref %d",
					i+1, gemsafe_prkeys[i].ref);
			ind += 9;
		}
		else {
			gemsafe_prkeys[i].label = NULL;
			gemsafe_cert[i].label = NULL;
			sc_log(card->ctx, "Key container %d is unallocated", i+1);
			ind += 8;
		}
		i++;
	}

	/* Delete additional key containers from the data structures if
	 * this card can't accommodate them.
	 */
	for (; i < gemsafe_cert_max; i++) {
		gemsafe_prkeys[i].label = NULL;
		gemsafe_cert[i].label = NULL;
	}

	/* Read entire file, then dissect in memory.
	 * Gemalto ClassicClient seems to do it the same way.
	 */
	iptr = ibuf + GEMSAFE_READ_QUANTUM;
	while ((size_t)(iptr - ibuf) < objlen) {
		r = sc_read_binary(card, iptr - ibuf, iptr,
				   MIN(GEMSAFE_READ_QUANTUM, objlen - (iptr - ibuf)), 0);
		if (r < 0) {
			sc_log(card->ctx, "Could not read cert object");
			return SC_ERROR_INTERNAL;
		}
		iptr += GEMSAFE_READ_QUANTUM;
	}

	/* Search buffer for certificates, they start with 0x3082. */
	i = 0;
	while (ind < objlen - 1) {
		if (ibuf[ind] == 0x30 && ibuf[ind+1] == 0x82) {
			/* Find next allocated key container */
			while (i < gemsafe_cert_max && gemsafe_cert[i].label == NULL)
				i++;
			if (i == gemsafe_cert_max) {
				sc_log(card->ctx, "Warning: Found orphaned certificate at offset %d", ind);
				return SC_SUCCESS;
			}
			/* DER cert len is encoded this way */
			if (ind+3 >= sizeof ibuf)
				return SC_ERROR_INVALID_DATA;
			certlen = ((((size_t) ibuf[ind+2]) << 8) | ibuf[ind+3]) + 4;
			sc_log(card->ctx,
			       "Found certificate of key container %d at offset %d, len %"SC_FORMAT_LEN_SIZE_T"u",
			       i+1, ind, certlen);
			gemsafe_cert[i].index = ind;
			gemsafe_cert[i].count = certlen;
			ind += certlen;
			i++;
		} else
			ind++;
	}

	/* Delete additional key containers from the data structures if
	 * they're missing on the card.
	 */
	for (; i < gemsafe_cert_max; i++) {
		if (gemsafe_cert[i].label) {
			sc_log(card->ctx, "Warning: Certificate of key container %d is missing", i+1);
			gemsafe_prkeys[i].label = NULL;
			gemsafe_cert[i].label = NULL;
		}
	}

	return SC_SUCCESS;
}

static int gemsafe_detect_card( sc_pkcs15_card_t *p15card)
{
	if (strcmp(p15card->card->name, "GemSAFE V1"))
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

static int sc_pkcs15emu_gemsafeV1_init( sc_pkcs15_card_t *p15card)
{
	int		    r;
	unsigned int    i;
	struct sc_path  path;
	struct sc_file *file = NULL;
	struct sc_card *card = p15card->card;
	struct sc_apdu  apdu;
	u8		    rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_log(p15card->card->ctx, "Setting pkcs15 parameters");

	if (p15card->tokeninfo->label)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = strdup(APPLET_NAME);
	if (!p15card->tokeninfo->label)
		return SC_ERROR_INTERNAL;

	if (p15card->tokeninfo->serial_number)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = strdup(DRIVER_SERIAL_NUMBER);
	if (!p15card->tokeninfo->serial_number)
		return SC_ERROR_INTERNAL;

	/* the GemSAFE applet version number */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0xdf, 0x03);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	/* Manual says Le=0x05, but should be 0x08 to return full version number */
	apdu.le = 0x08;
	apdu.lc = 0;
	apdu.datalen = 0;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;

	/* the manufacturer ID, in this case GemPlus */
	if (p15card->tokeninfo->manufacturer_id)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);
	if (!p15card->tokeninfo->manufacturer_id)
		return SC_ERROR_INTERNAL;

	/* determine allocated key containers and length of certificates */
	r = gemsafe_get_cert_len(card);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;

	/* set certs */
	sc_log(p15card->card->ctx, "Setting certificates");
	for (i = 0; i < gemsafe_cert_max; i++) {
		struct sc_pkcs15_id p15Id;
		struct sc_path path;

		if (gemsafe_cert[i].label == NULL)
			continue;
		sc_format_path(gemsafe_cert[i].path, &path);
		sc_pkcs15_format_id(gemsafe_cert[i].id, &p15Id);
		path.index = gemsafe_cert[i].index;
		path.count = gemsafe_cert[i].count;
		sc_pkcs15emu_add_cert(p15card, SC_PKCS15_TYPE_CERT_X509,
				      gemsafe_cert[i].authority, &path, &p15Id,
				      gemsafe_cert[i].label, gemsafe_cert[i].obj_flags);
	}

	/* set gemsafe_pin */
	sc_log(p15card->card->ctx, "Setting PIN");
	for (i=0; i < gemsafe_pin_max; i++) {
		struct sc_pkcs15_id	p15Id;
		struct sc_path path;

		sc_pkcs15_format_id(gemsafe_pin[i].id, &p15Id);
		sc_format_path(gemsafe_pin[i].path, &path);
		if (gemsafe_pin[i].atr_len == 0 ||
		   (gemsafe_pin[i].atr_len == p15card->card->atr.len &&
		    memcmp(p15card->card->atr.value, gemsafe_pin[i].atr,
			   p15card->card->atr.len) == 0)) {
			sc_pkcs15emu_add_pin(p15card, &p15Id, gemsafe_pin[i].label,
					     &path, gemsafe_pin[i].ref, gemsafe_pin[i].type,
					     gemsafe_pin[i].minlen, gemsafe_pin[i].maxlen,
					     gemsafe_pin[i].flags, gemsafe_pin[i].tries_left,
					     gemsafe_pin[i].pad_char, gemsafe_pin[i].obj_flags);
			break;
		}
	};

	/* set private keys */
	sc_log(p15card->card->ctx, "Setting private keys");
	for (i = 0; i < gemsafe_cert_max; i++) {
		struct sc_pkcs15_id p15Id, authId, *pauthId;
		struct sc_path path;
		int key_ref = 0x03;

		if (gemsafe_prkeys[i].label == NULL)
			continue;
		sc_pkcs15_format_id(gemsafe_prkeys[i].id, &p15Id);
		if (gemsafe_prkeys[i].auth_id) {
			sc_pkcs15_format_id(gemsafe_prkeys[i].auth_id, &authId);
			pauthId = &authId;
		} else
			pauthId = NULL;
		sc_format_path(gemsafe_prkeys[i].path, &path);
		/*
		 * The key ref may be different for different sites;
		 * by adding flags=n where the low order 4 bits can be
		 * the key ref we can force it.
		 */
		if ( p15card->card->flags & 0x0F) {
			key_ref = p15card->card->flags & 0x0F;
			sc_log(p15card->card->ctx, 
				 "Overriding key_ref %d with %d\n",
				 gemsafe_prkeys[i].ref, key_ref);
		} else
			key_ref = gemsafe_prkeys[i].ref;
		sc_pkcs15emu_add_prkey(p15card, &p15Id, gemsafe_prkeys[i].label,
				       SC_PKCS15_TYPE_PRKEY_RSA,
				       gemsafe_prkeys[i].modulus_len, gemsafe_prkeys[i].usage,
				       &path, key_ref, pauthId,
				       gemsafe_prkeys[i].obj_flags);
	}

	/* select the application DF */
	sc_log(p15card->card->ctx, "Selecting application DF");
	sc_format_path(GEMSAFE_APP_PATH, &path);
	r = sc_select_file(card, &path, &file);
	if (r != SC_SUCCESS || !file)
		return SC_ERROR_INTERNAL;
	/* set the application DF */
	sc_file_free(p15card->file_app);
	p15card->file_app = file;

	return SC_SUCCESS;
}

int sc_pkcs15emu_gemsafeV1_init_ex( sc_pkcs15_card_t *p15card,
			struct sc_aid *aid)
{
	if (gemsafe_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_gemsafeV1_init(p15card);
}

static sc_pkcs15_df_t *
sc_pkcs15emu_get_df(sc_pkcs15_card_t *p15card, unsigned int type)
{
	sc_pkcs15_df_t	*df;
	sc_file_t	*file;
	int		created = 0;

	while (1) {
		for (df = p15card->df_list; df; df = df->next) {
			if (df->type == type) {
				if (created)
					df->enumerated = 1;
				return df;
			}
		}

		assert(created == 0);

		file = sc_file_new();
		if (!file)
			return NULL;
		sc_format_path("11001101", &file->path);
		sc_pkcs15_add_df(p15card, type, &file->path);
		sc_file_free(file);
		created++;
	}
}

static int
sc_pkcs15emu_add_object(sc_pkcs15_card_t *p15card, int type,
		const char *label, void *data,
		const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_object_t *obj;
	int		df_type;

	obj = calloc(1, sizeof(*obj));

	obj->type  = type;
	obj->data  = data;

	if (label)
		strncpy(obj->label, label, sizeof(obj->label)-1);

	obj->flags = obj_flags;
	if (auth_id)
		obj->auth_id = *auth_id;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		df_type = SC_PKCS15_AODF;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		df_type = SC_PKCS15_PRKDF;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		df_type = SC_PKCS15_PUKDF;
		break;
	case SC_PKCS15_TYPE_CERT:
		df_type = SC_PKCS15_CDF;
		break;
	default:
		sc_log(p15card->card->ctx, "Unknown PKCS15 object type %d", type);
		free(obj);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	obj->df = sc_pkcs15emu_get_df(p15card, df_type);
	sc_pkcs15_add_object(p15card, obj);

	return 0;
}

static int
sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id, const char *label,
                const sc_path_t *path, int ref, int type,
                unsigned int min_length,
                unsigned int max_length,
                int flags, int tries_left, const char pad_char, int obj_flags)
{
	sc_pkcs15_auth_info_t *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);

	info->auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	info->auth_method = SC_AC_CHV;
	info->auth_id           = *id;
	info->attrs.pin.min_length        = min_length;
	info->attrs.pin.max_length        = max_length;
	info->attrs.pin.stored_length     = max_length;
	info->attrs.pin.type              = type;
	info->attrs.pin.reference         = ref;
	info->attrs.pin.flags             = flags;
	info->attrs.pin.pad_char          = pad_char;
	info->tries_left        = tries_left;
	info->logged_in = SC_PIN_STATE_UNKNOWN;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, SC_PKCS15_TYPE_AUTH_PIN, label, info, NULL, obj_flags);
}

static int
sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
		int type, int authority,
		const sc_path_t *path,
		const sc_pkcs15_id_t *id,
                const char *label, int obj_flags)
{
	sc_pkcs15_cert_info_t *info;
	info = calloc(1, sizeof(*info));
	if (!info)
	{
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	info->id		= *id;
	info->authority		= authority;
	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, NULL, obj_flags);
}

static int
sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id,
                const char *label,
                int type, unsigned int modulus_length, int usage,
                const sc_path_t *path, int ref,
                const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_prkey_info_t *info;

	info = calloc(1, sizeof(*info));
	if (!info)
	{
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	info->id                = *id;
	info->modulus_length    = modulus_length;
	info->usage             = usage;
	info->native            = 1;
	info->access_flags      = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
                                | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
                                | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
                                | SC_PKCS15_PRKEY_ACCESS_LOCAL;
	info->key_reference     = ref;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label,
			info, auth_id, obj_flags);
}

/* SC_IMPLEMENT_DRIVER_VERSION("0.9.4") */
