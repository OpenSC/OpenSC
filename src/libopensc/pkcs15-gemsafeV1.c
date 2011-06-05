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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"

#define MANU_ID			"Gemplus"
#define APPLET_NAME		"GemSAFE V1"
#define DRIVER_SERIAL_NUMBER	"v0.9"

int sc_pkcs15emu_gemsafeV1_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

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
	const char *label;
	int	    authority;
	const char *path;
	const char *id;
	int         obj_flags;
} cdata;

const cdata gemsafe_cert[] = {
	{"DS certificate", 0, "3F0016000004","45", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{NULL, 0, NULL, 0, 0}
};

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	int         flags;
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata;

const pindata gemsafe_pin[] = {
	{ "01", "DS pin", NULL, 0x01, SC_PKCS15_PIN_TYPE_BCD,
	  16, 6, SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_LOCAL,
	  3, 0xFF,
	  SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE },
	{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};

typedef struct prdata_st {
	const char *id;
	const char *label;
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

const prdata gemsafe_prkeys[] = {
	{ "45", "DS key", 1024, USAGE_AUT, NULL,
	  0x03, "01", SC_PKCS15_CO_FLAG_PRIVATE},
	{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
};

static int gemsafe_get_cert_len(sc_card_t *card, sc_path_t *path, 
	int *key_ref)
{
	const char *fn_name = "gemsafe_get_cert_len";
	int r;
	int ind;
	u8  ibuf[248];
	struct sc_file *file;
	size_t objlen, certlen;
	unsigned int block=0;
	int found = 0;
	unsigned int offset=0, index_local, i=0;

	r = sc_select_file(card, path, &file);
	if (r < 0)
		return 0;

	/* Apparently, the Applet max read "quanta" is 248 bytes */
	/* Initial read */
	r = sc_read_binary(card, offset, ibuf, 248, 0);
	if (r < 0)
		return 0;

	/* Actual stored object size is encoded in first 2 bytes
	 * (allocated EF space is much greater!)
	 */
	objlen = (((size_t) ibuf[0]) << 8) | ibuf[1];
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Certificate object is of size: %d\n", fn_name, objlen);

	if (objlen < 1 || objlen > 10240) {
	    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Invalid object size: %d\n", fn_name, objlen);
	    return 0;
	}

	/*
	 * We need to find the private key associated with the cert
	 * It looks like the first thing in the block is a table of
	 * which keys are allocated. 
	 * We will look for the first allocated key, and save the 
	 * key_ref. The table is small and is in the first 248 bytes.
	 * If for some reason this is not true, we can still override
	 * the key_ref in the opensc.conf with flag = n.
	 */
	ind = 2; /* skip length */
	while (ibuf[ind] == 0x01) {
		if (ibuf[ind+1] == 0xFE) {
			*key_ref = ibuf[ind+4];
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Using key_ref %d found at offset %d\n",
					*key_ref, ind);
			break;
		}
		ind = ind + 8;
	}

	/* Using (block+1) in while loop avoids using final cert object data block */
	while (!found && ( (block+1) * 248 < objlen) ) {
	    /* Check current buffer */
	    for (i = 0; i < 248; i++) {
	    	if (ibuf[i] == 0x30 && ibuf[i+1] == 0x82) {
		    found = 1;
		    break;
		}
	    }

	    /* Grab another buffer */
	    if (!found) {
		block++;
		offset = block*248;
		r = sc_read_binary(card, offset, ibuf, 248, 0);
		if (r < 0) {
		    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Could not read cert object\n", fn_name);
		    return 0;
		}
	    }

	}

	index_local = block*248 + i;

	/* DER Cert len is encoded this way */
	certlen = ((((size_t) ibuf[i+2]) << 8) | ibuf[i+3]) + 4;
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%s: certlen: %04X\n", fn_name, certlen);

	path->index = index_local;
	path->count = certlen;

	return 1;

}

static int gemsafe_detect_card( sc_pkcs15_card_t *p15card)
{
	if (strcmp(p15card->card->name, "GemSAFE V1"))
		return SC_ERROR_WRONG_CARD;

    return SC_SUCCESS;
}

static int sc_pkcs15emu_gemsafeV1_init( sc_pkcs15_card_t *p15card)
{
    const char *fn_name = "sc_pkcs15emu_gemsafe_init";

    int    r, i;
	int	   key_ref = 0x03; 
    struct sc_path path;
    struct sc_file *file = NULL;
    struct sc_card *card = p15card->card;
    struct sc_apdu apdu;
    u8     rbuf[SC_MAX_APDU_BUFFER_SIZE];

    sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Setting pkcs15 parameters\n", fn_name);

    if (p15card->tokeninfo->label)
    	free(p15card->tokeninfo->label);
    p15card->tokeninfo->label = malloc(strlen(APPLET_NAME) + 1);
    if (!p15card->tokeninfo->label)
    	return SC_ERROR_INTERNAL;
    strcpy(p15card->tokeninfo->label, APPLET_NAME);

    if (p15card->tokeninfo->serial_number)
	    free(p15card->tokeninfo->serial_number);
    p15card->tokeninfo->serial_number = malloc(strlen(DRIVER_SERIAL_NUMBER) + 1);
    if (!p15card->tokeninfo->serial_number)
	    return SC_ERROR_INTERNAL;
    strcpy(p15card->tokeninfo->serial_number, DRIVER_SERIAL_NUMBER);

    /* the GemSAFE applet version number */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0xdf, 0x03);
    apdu.cla = 0x80;
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    /* Manual says Le=0x05, but should be 0x08 to return full version numer */
    apdu.le = 0x08;
    apdu.lc = 0;
    apdu.datalen = 0;
    r = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
	    return SC_ERROR_INTERNAL;
    if (r != SC_SUCCESS)
	    return SC_ERROR_INTERNAL;

    /* the manufacturer ID, in this case GemPlus */
    if (p15card->tokeninfo->manufacturer_id)
	    free(p15card->tokeninfo->manufacturer_id);
    p15card->tokeninfo->manufacturer_id = malloc(strlen(MANU_ID) + 1);
    if (!p15card->tokeninfo->manufacturer_id)
	    return SC_ERROR_INTERNAL;
    strcpy(p15card->tokeninfo->manufacturer_id, MANU_ID);

    /* set certs */
    sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Setting certificate\n", fn_name);
    for (i = 0; gemsafe_cert[i].label; i++) {
	    struct sc_pkcs15_id  p15Id;

	    sc_format_path(gemsafe_cert[i].path, &path);
	    if (!gemsafe_get_cert_len(card, &path, &key_ref))
		    /* skip errors */
		    continue;
	    sc_pkcs15_format_id(gemsafe_cert[i].id, &p15Id);
	    sc_pkcs15emu_add_cert(p15card, SC_PKCS15_TYPE_CERT_X509,
			    gemsafe_cert[i].authority, &path, &p15Id,
			    gemsafe_cert[i].label, gemsafe_cert[i].obj_flags);
    }
    /* set gemsafe_pin */
    sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Setting PIN\n", fn_name);
    for (i = 0; gemsafe_pin[i].label; i++) {
	    struct sc_pkcs15_id  p15Id;

	    sc_pkcs15_format_id(gemsafe_pin[i].id, &p15Id);
	    sc_pkcs15emu_add_pin(p15card, &p15Id, gemsafe_pin[i].label,
			    &path, gemsafe_pin[i].ref, gemsafe_pin[i].type,
			    gemsafe_pin[i].minlen, gemsafe_pin[i].maxlen,
			    gemsafe_pin[i].flags,
			    gemsafe_pin[i].tries_left, gemsafe_pin[i].pad_char,
			    gemsafe_pin[i].obj_flags);
    }
    /* set private keys */
    sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "%s: Setting private key\n", fn_name);
    for (i = 0; gemsafe_prkeys[i].label; i++) {
	    struct sc_pkcs15_id p15Id,
				authId, *pauthId;
	    sc_pkcs15_format_id(gemsafe_prkeys[i].id, &p15Id);
	    if (gemsafe_prkeys[i].auth_id) {
		    sc_pkcs15_format_id(gemsafe_prkeys[i].auth_id, &authId);
		    pauthId = &authId;
	    } else
		    pauthId = NULL;
			/*
			 * the key ref may be different for different sites 
			 * by adding flags=n where the low order 4 bits can be
			 * the key ref we can force it. 
			 */
			if ( p15card->card->flags & 0x0F) {
				key_ref = p15card->card->flags & 0x0F;
				sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
					"Overriding key_ref  with %d\n", key_ref);
			} 
	    sc_pkcs15emu_add_prkey(p15card, &p15Id, gemsafe_prkeys[i].label,
			    SC_PKCS15_TYPE_PRKEY_RSA,
			    gemsafe_prkeys[i].modulus_len, gemsafe_prkeys[i].usage,
			    &path, key_ref, pauthId,
			    gemsafe_prkeys[i].obj_flags);
    }

    /* select the application DF */
    sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,"%s: Selecting application DF\n", fn_name);
    sc_format_path("3F001600", &path);
    r = sc_select_file(card, &path, &file);
    if (r != SC_SUCCESS || !file)
	    return SC_ERROR_INTERNAL;
    /* set the application DF */
    if (p15card->file_app)
	    free(p15card->file_app);
    p15card->file_app = file;

    return SC_SUCCESS;

}

int sc_pkcs15emu_gemsafeV1_init_ex( sc_pkcs15_card_t *p15card,
			sc_pkcs15emu_opt_t *opts)
{
    if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
	    return sc_pkcs15emu_gemsafeV1_init(p15card);
    else {
	    int r = gemsafe_detect_card(p15card);
	    if (r)
		    return SC_ERROR_WRONG_CARD;
	    return sc_pkcs15emu_gemsafeV1_init(p15card);
    }
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
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"Unknown PKCS15 object type %d\n", type);
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
	info->auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	info->auth_id           = *id;
	info->attrs.pin.min_length        = min_length;
	info->attrs.pin.max_length        = max_length;
	info->attrs.pin.stored_length     = max_length;
	info->attrs.pin.type              = type;
	info->attrs.pin.reference         = ref;
	info->attrs.pin.flags             = flags;
	info->attrs.pin.pad_char          = pad_char;
	info->tries_left        = tries_left;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card,
	                               SC_PKCS15_TYPE_AUTH_PIN,
	                               label, info, NULL, obj_flags);
}

static int
sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
		int type, int authority,
		const sc_path_t *path,
		const sc_pkcs15_id_t *id,
                const char *label, int obj_flags)
{
	/* const char *label = "Certificate"; */
	sc_pkcs15_cert_info_t *info;
	info = calloc(1, sizeof(*info));
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

#if 0
static int
sc_pkcs15emu_add_pubkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label, int type,
		unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_pubkey_info_t *info;

	info = calloc(1, sizeof(*info));
	info->id		= *id;
	info->modulus_length	= modulus_length;
	info->usage		= usage;
	info->access_flags	= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
	info->key_reference	= ref;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, auth_id, obj_flags);
}
#endif

/* SC_IMPLEMENT_DRIVER_VERSION("0.9.4") */
