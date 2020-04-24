/*
 * partial PKCS15 emulation for Coolkey cards
 *
 * Copyright (C) 2005,2006,2007,2008,2009,2010
 *               Douglas E. Engert <deengert@anl.gov>
 *               2004, Nils Larsch <larsch@trustcenter.de>
 * Copyright (C) 2006, Identity Alliance,
 *               Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
 * Copyright (C) 2016, Red Hat, Inc.
 *
 * Coolkey driver author: Robert Relyea <rrelyea@redhat.com>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "internal.h"
#include "cardctl.h"
#include "asn1.h"
#include "pkcs15.h"
#include "../pkcs11/pkcs11.h"

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;
	int         tries_left;
	const unsigned char  pad_char;
	int         obj_flags;
} pindata;

static int coolkey_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->type < SC_CARD_TYPE_COOLKEY_GENERIC
		|| card->type >= SC_CARD_TYPE_COOLKEY_GENERIC+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

static int
coolkey_get_object(sc_card_t *card, unsigned long object_id, sc_cardctl_coolkey_object_t **obj) {
	sc_cardctl_coolkey_find_object_t fobj;
	int r;

	fobj.type = SC_CARDCTL_COOLKEY_FIND_BY_ID;
	fobj.find_id = object_id;
	fobj.obj = NULL;
	r = sc_card_ctl(card, SC_CARDCTL_COOLKEY_FIND_OBJECT, &fobj);
	if (r < 0) {
		return r;
	}
	*obj = fobj.obj;
	return SC_SUCCESS;
}


/*
 * fetch attributes from an object
 */
static int
coolkey_get_attribute(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE type, const u8 **val, size_t *val_len, u8 *data_type) {
	sc_cardctl_coolkey_attribute_t attribute;
	int r;

	attribute.object = obj;
	attribute.attribute_type = type;

	r = sc_card_ctl(card, SC_CARDCTL_COOLKEY_GET_ATTRIBUTE, &attribute);
	if (r < 0) {
		return r;
	}
	*val = attribute.attribute_value;
	*val_len = attribute.attribute_length;
	if (data_type) {
		*data_type = attribute.attribute_data_type;
	}
	return SC_SUCCESS;
}

static int
coolkey_find_matching_cert(sc_card_t *card, sc_cardctl_coolkey_object_t *in_obj, sc_cardctl_coolkey_object_t **cert_obj) {
	sc_cardctl_coolkey_find_object_t fobj;
	sc_cardctl_coolkey_attribute_t template[2];
	u8 obj_class[4];
	int r;

	/* we are searching for certs .. */
	template[0].attribute_type = CKA_CLASS;
	template[0].attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG;
	template[0].attribute_length = sizeof(obj_class);
	template[0].attribute_value = obj_class;
	ulong2bebytes(obj_class, CKO_CERTIFICATE);

	/* fetch the current object's CKA_ID */
	template[1].attribute_type = CKA_ID;
	template[1].object = in_obj;
	r = sc_card_ctl(card, SC_CARDCTL_COOLKEY_GET_ATTRIBUTE, &template[1]);
	if (r < 0) {
		return r;
	}
	template[0].object = NULL; /*paranoia */
	template[1].object = NULL; /*paranoia */

	/* now find the cert that has the ID */
	fobj.type = SC_CARDCTL_COOLKEY_FIND_BY_TEMPLATE;
	fobj.obj = NULL;
	fobj.coolkey_template = &template[0];
	fobj.template_count=2;
	r = sc_card_ctl(card, SC_CARDCTL_COOLKEY_FIND_OBJECT, &fobj);
	if (r < 0) {
		return r;
	}
	*cert_obj = fobj.obj;
	return SC_SUCCESS;
}

static int
coolkey_get_attribute_ulong(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE type, CK_ULONG *value)
{
	const u8 *val;
	size_t val_len;
	u8 data_type;
	int r;

	r  = coolkey_get_attribute(card, obj, type, &val, &val_len, &data_type);
	if (r < 0) {
		return r;
	}
	if ((data_type != SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG) &&
	    (val_len != sizeof(CK_ULONG))) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	*value = bebytes2ulong(val);
	return SC_SUCCESS;
}

static int
coolkey_get_attribute_boolean(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE attr_type)
{
	int r;
	const u8 *val;
	size_t val_len;

	r = coolkey_get_attribute(card, obj, attr_type, &val, &val_len, NULL);
	if (r < 0) {
		/* attribute not valid for this object, set boolean to false */
		return 0;
	}
	if ((val_len == 1) && (*val == 1)) {
		return 1;
	}
	return 0;
}

static int
coolkey_get_attribute_bytes(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE type, u8 *data, size_t *data_len, size_t max_data_len)
{
	const u8 *val;
	size_t val_len;
	int r;

	r = coolkey_get_attribute(card, obj, type, &val, &val_len, NULL);
	if (r < 0) {
		return r;
	}
	if (val_len > max_data_len) {
		val_len = max_data_len;
	}
	memcpy(data, val, val_len);
	*data_len = val_len;
	return SC_SUCCESS;
}

static int
coolkey_get_attribute_bytes_alloc(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE type, u8 **data, size_t *data_len)
{
	const u8 *val;
	size_t val_len;
	int r;

	r = coolkey_get_attribute(card, obj, type, &val, &val_len, NULL);
	if (r < 0) {
		return r;
	}
	*data = malloc(val_len);
	if (*data == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(*data, val, val_len);
	*data_len = val_len;
	return SC_SUCCESS;
}

static int
coolkey_get_id(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, struct sc_pkcs15_id *id)
{
	return coolkey_get_attribute_bytes(card, obj, CKA_ID, id->value , &id->len, sizeof(id->value));
}

/*
 * A number of opensc structure have the same layout, use a common function to fill them
 * int:
 *     structure name      first parameter                 second parameter
 *     sc_lv_data          unsigned char * value           size_t len
 *     sc_pkcs15_data         u8 *data                     size_t data_len
 *     sc_pkcs15_bignum       u8 *data                     size_t len
 *     sc_pkcs15_der          u8 *value	                   size_t len
 *     sc_pkcs15_u8           u8 *value                    size_t len
 *
 * The following can properly assign all of them
 */
int
coolkey_get_attribute_lv(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_ATTRIBUTE_TYPE type, void *ptr)
{
	struct sc_pkcs15_data *item = (struct sc_pkcs15_data *)ptr;
	return coolkey_get_attribute_bytes_alloc(card, obj, type, &item->data, &item->data_len);
}

#define COOLKEY_ID_CERT ((unsigned long)'c')
#define COOLKEY_ID_KEY ((unsigned long)'k')
#define COOLKEY_ID_CERT_DATA ((unsigned long)'C')

static unsigned long
coolkey_get_object_type(unsigned long object_id) { return ((object_id >> 24 ) & 0xff); }

static unsigned long
coolkey_make_new_id(unsigned long object_id, unsigned long id_type)
{ return ((object_id  & 0x00ffffffUL)|(id_type << 24)); }


/*
 * We need cert data to fill in some of our keys. Also, some older tokens store the cert data in a separate
 * object from the rest of the cert attributes. This function handles both of these complications
 */
static int
coolkey_get_certificate(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, struct sc_pkcs15_der *cert)
{
	sc_cardctl_coolkey_object_t *cert_obj;
	unsigned long object_id;
	int r;

	cert_obj = obj;
	if (coolkey_get_object_type(obj->id) != COOLKEY_ID_CERT) {
		r = coolkey_find_matching_cert(card, obj, &cert_obj);
		if (r < 0) {
			return r;
		}
	}
	r = coolkey_get_attribute_lv(card, cert_obj, CKA_VALUE, cert);
	if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND) {
		object_id = coolkey_make_new_id(cert_obj->id, COOLKEY_ID_CERT_DATA);
		r = coolkey_get_object(card, object_id, &cert_obj);
		if (r < 0) {
			return r;
		}
		/* fill in cert data */
		cert->value = malloc(cert_obj->length);
		if (cert->value == NULL) {
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(cert->value, cert_obj->data, cert_obj->length);
		cert->len = cert_obj->length;
		return SC_SUCCESS;
	}
	return r;
}



struct coolkey_attr_flags {
	CK_ATTRIBUTE_TYPE attribute_type;
	unsigned int pkcs15_flags;
};

static struct coolkey_attr_flags usage_table[] = {
	{ CKA_ENCRYPT,          SC_PKCS15_PRKEY_USAGE_ENCRYPT       },
	{ CKA_DECRYPT,          SC_PKCS15_PRKEY_USAGE_DECRYPT       },
	{ CKA_SIGN,             SC_PKCS15_PRKEY_USAGE_SIGN          },
	{ CKA_SIGN_RECOVER,     SC_PKCS15_PRKEY_USAGE_SIGNRECOVER   },
	{ CKA_WRAP,             SC_PKCS15_PRKEY_USAGE_WRAP          },
	{ CKA_UNWRAP,           SC_PKCS15_PRKEY_USAGE_UNWRAP        },
	{ CKA_VERIFY,           SC_PKCS15_PRKEY_USAGE_VERIFY        },
	{ CKA_VERIFY_RECOVER,   SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
	{ CKA_DERIVE,           SC_PKCS15_PRKEY_USAGE_DERIVE        }
};

static struct coolkey_attr_flags access_table[] = {
	{ CKA_SENSITIVE,        SC_PKCS15_PRKEY_ACCESS_SENSITIVE       },
    { CKA_EXTRACTABLE,      SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE     },
    { CKA_ALWAYS_SENSITIVE, SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE },
    { CKA_NEVER_EXTRACTABLE,SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE},
    { CKA_LOCAL,            SC_PKCS15_PRKEY_ACCESS_LOCAL           }
};

static struct coolkey_attr_flags flag_table[] = {
	{ CKA_PRIVATE,          SC_PKCS15_CO_FLAG_PRIVATE       },
	{ CKA_MODIFIABLE,       SC_PKCS15_CO_FLAG_MODIFIABLE    }
};

static int usage_table_size = sizeof(usage_table)/sizeof(usage_table[0]);
static int access_table_size = sizeof(access_table)/sizeof(access_table[0]);
static int flag_table_size = sizeof(flag_table)/sizeof(flag_table[0]);

static int
coolkey_set_bool_flags(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, unsigned int *flags_ptr, struct coolkey_attr_flags *table, int table_size)
{
	unsigned int flags = 0;
	int i;

	for (i=0; i< table_size; i++) {
		if (coolkey_get_attribute_boolean(card, obj, table[i].attribute_type)) {
			flags |= table[i].pkcs15_flags;
		}
	}
	*flags_ptr = flags;
	return SC_SUCCESS;
}

/* map a cert usage and algorithm to public and private key usages */
static int
coolkey_get_usage(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, unsigned int *usage_ptr)
{
	return coolkey_set_bool_flags(card, obj, usage_ptr, usage_table, usage_table_size);
}

/* map a cert usage and algorithm to public and private key usages */
static int
coolkey_get_flags(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, unsigned int *flag_ptr)
{
	return coolkey_set_bool_flags(card, obj, flag_ptr, flag_table, flag_table_size);
}

static int
coolkey_get_access(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, unsigned int *access_ptr)
{
	return coolkey_set_bool_flags(card, obj, access_ptr, access_table, access_table_size);
}


/*
 * turn a coolkey object into a pkcss 15 pubkey. object should already be type
 * CKO_PUBLIC_KEY */
static sc_pkcs15_pubkey_t *
coolkey_make_public_key(sc_card_t *card, sc_cardctl_coolkey_object_t *obj, CK_KEY_TYPE key_type)
{
	sc_pkcs15_pubkey_t *key;
	int r;

	key = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (!key)
		return NULL;
	switch (key_type) {
	case CKK_RSA:
		key->algorithm = SC_ALGORITHM_RSA;
		r = coolkey_get_attribute_lv(card, obj, CKA_MODULUS, &key->u.rsa.modulus);
		if (r != SC_SUCCESS) {
			goto fail;
		}
		r = coolkey_get_attribute_lv(card, obj, CKA_PUBLIC_EXPONENT, &key->u.rsa.exponent);
		if (r != SC_SUCCESS) {
			goto fail;
		}
		break;
	case CKK_EC:
		key->algorithm = SC_ALGORITHM_EC;
		r = coolkey_get_attribute_bytes_alloc(card, obj, CKA_EC_POINT, &key->u.ec.ecpointQ.value, &key->u.ec.ecpointQ.len);
	    if(r < 0) {
			goto fail;
		}
		r = coolkey_get_attribute_bytes_alloc(card, obj, CKA_EC_PARAMS,
				&key->u.ec.params.der.value, &key->u.ec.params.der.len);
		if (r < 0) {
			goto fail;
		}
		r = sc_pkcs15_fix_ec_parameters(card->ctx, &key->u.ec.params);
		if (r < 0) {
			goto fail;
		}
		break;
	}
	return key;
fail:
	sc_pkcs15_free_pubkey(key);

	/* now parse the DER cert */
	return NULL;
}


static sc_pkcs15_pubkey_t *
coolkey_get_public_key_from_certificate(sc_pkcs15_card_t *p15card, sc_cardctl_coolkey_object_t *obj)
{
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_cert_t *cert_out = NULL;
	sc_pkcs15_pubkey_t *key = NULL;
	int r;

	cert_info.value.value = NULL;
	r = coolkey_get_certificate(p15card->card, obj, &cert_info.value);
	if (r < 0) {
		goto fail;
	}
	r = sc_pkcs15_read_certificate(p15card, &cert_info, &cert_out);
	if (r < 0) {
		goto fail;
	}
	key = cert_out->key;
	cert_out->key = NULL; /* adopt the key from the cert */
fail:
	if (cert_out) {
		sc_pkcs15_free_certificate(cert_out);
	}
	if (cert_info.value.value) {
		free(cert_info.value.value);
	}
	return key;
}

static sc_pkcs15_pubkey_t *
coolkey_get_public_key(sc_pkcs15_card_t *p15card, sc_cardctl_coolkey_object_t *obj, CK_KEY_TYPE key_type)
{
	sc_pkcs15_pubkey_t *key;

	key = coolkey_make_public_key(p15card->card, obj, key_type);
	if (key) {
		return key;
	}
	return coolkey_get_public_key_from_certificate(p15card, obj);
}

static int sc_pkcs15emu_coolkey_init(sc_pkcs15_card_t *p15card)
{
	static const pindata pins[] = {
		{ "1", NULL, "", 0x00,
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  32, 4, 32,
		  SC_PKCS15_PIN_FLAG_INITIALIZED,
		  -1, 0xFF,
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};

	/*
	 * The size of the key or the algid is not really known
	 * but can be derived from the certificates.
	 * the cert, pubkey and privkey are a set.
	 * Key usages bits taken from certificate key usage extension.
	 */

	int    r, i;
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;
	int count;
	struct sc_pkcs15_object *obj;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&serial, 0, sizeof(serial));

	/* coolkey caches a nonce once it logs in, don't keep the pin around. The card will
	 * stay logged in until it's been pulled from the reader, in which case you want to reauthenticate
	 * anyway */
	p15card->opts.use_pin_cache = 0;


	/* get the token info from the card */
	r = sc_card_ctl(card, SC_CARDCTL_COOLKEY_GET_TOKEN_INFO, p15card->tokeninfo);
	if (r < 0) {
		/* put some defaults in if we didn't succeed */
		p15card->tokeninfo->label = strdup("Coolkey");
		p15card->tokeninfo->manufacturer_id = strdup("Unknown");
		p15card->tokeninfo->serial_number = strdup("00000000");
	}

	/* set pins */
	sc_log(card->ctx,  "Coolkey adding pins...");
	for (i = 0; pins[i].id; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;
		const char * label;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		sc_pkcs15_format_id(pins[i].id, &pin_info.auth_id);
		pin_info.attrs.pin.reference     = pins[i].ref;
		pin_info.attrs.pin.flags         = pins[i].flags;
		pin_info.attrs.pin.type          = pins[i].type;
		pin_info.attrs.pin.min_length    = pins[i].minlen;
		pin_info.attrs.pin.stored_length = pins[i].storedlen;
		pin_info.attrs.pin.max_length    = pins[i].maxlen;
		pin_info.attrs.pin.pad_char      = pins[i].pad_char;
		sc_format_path(pins[i].path, &pin_info.path);
		pin_info.tries_left    = -1;

		label = pins[i].label? pins[i].label : p15card->tokeninfo->label;
		sc_log(card->ctx,  "Coolkey Adding pin %d label=%s",i, label);
		strncpy(pin_obj.label, label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags = pins[i].obj_flags;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	/* set other objects */
	r = (card->ops->card_ctl)(card, SC_CARDCTL_COOLKEY_INIT_GET_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not initiate objects.");

	sc_log(card->ctx,  "Iterating over %d objects", count);
	for (i = 0; i < count; i++) {
		struct sc_cardctl_coolkey_object     coolkey_obj;
		struct sc_pkcs15_object    obj_obj;
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_prkey_info prkey_info;
		sc_pkcs15_pubkey_t *key = NULL;
		void *obj_info = NULL;
		int obj_type = 0;
		CK_KEY_TYPE key_type;
		CK_OBJECT_CLASS obj_class;
		size_t len;

		r = (card->ops->card_ctl)(card, SC_CARDCTL_COOLKEY_GET_NEXT_OBJECT, &coolkey_obj);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);

		sc_log(card->ctx, "Loading object %d", i);
		memset(&obj_obj, 0, sizeof(obj_obj));
		/* coolkey applets have label only on the certificates,
		 * but we should copy it also to the keys matching the same ID */
		coolkey_get_attribute_bytes(card, &coolkey_obj, CKA_LABEL, (u8 *)obj_obj.label, &len, sizeof(obj_obj.label));
		coolkey_get_flags(card, &coolkey_obj, &obj_obj.flags);
		if (obj_obj.flags & SC_PKCS15_CO_FLAG_PRIVATE) {
			sc_pkcs15_format_id(pins[0].id, &obj_obj.auth_id);
		}

		r = coolkey_get_attribute_ulong(card, &coolkey_obj, CKA_CLASS, &obj_class);
		if (r < 0) {
			goto fail;
		}
		switch (obj_class) {
		case CKO_PRIVATE_KEY:
			sc_log(card->ctx, "Processing private key object %d", i);
			r = coolkey_get_attribute_ulong(card, &coolkey_obj, CKA_KEY_TYPE, &key_type);
			/* default to CKK_RSA */
			if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND) {
				key_type = CKK_RSA;
				r = SC_SUCCESS;
			}
			if (r < 0) {
				goto fail;
			}
			/* set the info values */
			obj_info = &prkey_info;
			memset(&prkey_info, 0, sizeof(prkey_info));
			coolkey_get_id(card, &coolkey_obj, &prkey_info.id);
			prkey_info.path = coolkey_obj.path;
			prkey_info.key_reference = coolkey_obj.id;
			prkey_info.native = 1;
			coolkey_get_usage(card, &coolkey_obj, &prkey_info.usage);
			coolkey_get_access(card, &coolkey_obj, &prkey_info.access_flags);
			key = coolkey_get_public_key(p15card, &coolkey_obj, key_type);
			if (key_type == CKK_RSA) {
				obj_type = SC_PKCS15_TYPE_PRKEY_RSA;
				if (key) {
					prkey_info.modulus_length = key->u.rsa.modulus.len*8;
				}
			} else if (key_type == CKK_EC) {
				obj_type = SC_PKCS15_TYPE_PRKEY_EC;
				if (key) {
					prkey_info.field_length = key->u.ec.params.field_length;
				}
			} else {
				goto fail;
			}
			break;

		case CKO_PUBLIC_KEY:
			sc_log(card->ctx, "Processing public key object %d", i);
			r = coolkey_get_attribute_ulong(card, &coolkey_obj, CKA_KEY_TYPE, &key_type);
			/* default to CKK_RSA */
			if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND) {
				key_type = CKK_RSA;
				r = SC_SUCCESS;
			}
			if (r < 0) {
				goto fail;
			}
			key = coolkey_get_public_key(p15card, &coolkey_obj, key_type);
			if (key == NULL) {
				goto fail;
			}
			/* set the info values */
			obj_info = &pubkey_info;
			memset(&pubkey_info, 0, sizeof(pubkey_info));
			r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, key, &pubkey_info.direct.spki.value,
				&pubkey_info.direct.spki.len);
			if (r < 0)
				goto fail;
			coolkey_get_id(card, &coolkey_obj, &pubkey_info.id);
			pubkey_info.path = coolkey_obj.path;
			pubkey_info.native = 1;
			pubkey_info.key_reference = coolkey_obj.id;
			coolkey_get_usage(card, &coolkey_obj, &pubkey_info.usage);
			coolkey_get_access(card, &coolkey_obj, &pubkey_info.access_flags);
			if (key_type == CKK_RSA) {
				obj_type = SC_PKCS15_TYPE_PUBKEY_RSA;
				pubkey_info.modulus_length = key->u.rsa.modulus.len*8;
			} else if (key_type == CKK_EC) {
				obj_type = SC_PKCS15_TYPE_PUBKEY_EC;
				pubkey_info.field_length = key->u.ec.params.field_length;
			} else {
				goto fail;
			}
			/* set the obj values */
			obj_obj.emulated = key;
			key = NULL;
			break;

		case CKO_CERTIFICATE:
			sc_log(card->ctx, "Processing certificate object %d", i);
			obj_info = &cert_info;
			memset(&cert_info, 0, sizeof(cert_info));
			coolkey_get_id(card, &coolkey_obj, &cert_info.id);
			cert_info.path = coolkey_obj.path;
			obj_type = SC_PKCS15_TYPE_CERT_X509;

			/* following will find the cached cert in cert_info */
			r = coolkey_get_certificate(card, &coolkey_obj, &cert_info.value);
			if (r < 0) {
				goto fail;
			}
			break;


		default:
			/* no other recognized types which are stored 'on card' */
			sc_log(card->ctx, "Unknown object type %lu, skipping", obj_class);
			continue;
		}

		r = sc_pkcs15emu_object_add(p15card, obj_type, &obj_obj, obj_info);
		if (r != SC_SUCCESS)
			sc_log(card->ctx, "sc_pkcs15emu_object_add() returned %d", r);
fail:
		if (key) { sc_pkcs15_free_pubkey(key); }

	}
	r = (card->ops->card_ctl)(card, SC_CARDCTL_COOLKEY_FINAL_GET_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not finalize objects.");

	/* Iterate over all the created objects and fill missing labels */
	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		struct sc_pkcs15_id *id = NULL;
		struct sc_pkcs15_object *cert_object;

		/* label non-empty -- do not overwrite */
		if (obj->label[0] != '\0')
			continue;

		switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PUBKEY:
			id = &((struct sc_pkcs15_pubkey_info *)obj->data)->id;
			break;
		case SC_PKCS15_TYPE_PRKEY:
			id = &((struct sc_pkcs15_prkey_info *)obj->data)->id;
			break;
		default:
			/* We do not care about other objects */
			continue;
		}
		r = sc_pkcs15_find_cert_by_id(p15card, id, &cert_object);
		if (r != 0)
			continue;

		sc_log(card->ctx, "Copy label \"%s\" from cert to key object",
			cert_object->label);
		memcpy(obj->label, cert_object->label, SC_PKCS15_MAX_LABEL_SIZE);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_coolkey_init_ex(sc_pkcs15_card_t *p15card,
		struct sc_aid *aid)
{
	sc_card_t      *card = p15card->card;
	sc_context_t    *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = coolkey_detect_card(p15card);
	if (rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	rv = sc_pkcs15emu_coolkey_init(p15card);

	LOG_FUNC_RETURN(ctx, rv);
}
