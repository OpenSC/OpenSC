/*
 * card-coolkey.c: Support for Coolkey
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2006,2007,2008,2009,2010 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
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

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <sys/types.h>

#ifdef ENABLE_OPENSSL
	/* openssl only needed for card administration */
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#endif /* ENABLE_OPENSSL */

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif
#include "iso7816.h"
#include "gp.h"
#include "../pkcs11/pkcs11.h"



#define COOLKEY_MAX_SIZE 4096		/* arbitrary, just needs to be 'large enough' */

/*
 *  COOLKEY hardware and APDU constants
 */
#define COOLKEY_MAX_CHUNK_SIZE 240 /* must be less than 255-8 */

/* ISO 7816 CLA values used by COOLKEY */
#define ISO7816_CLASS           0x00
#define COOLKEY_CLASS           0xb0

/* ISO 71816 INS values used by COOLKEY */
#define ISO7816_INS_SELECT_FILE 0xa4

/* COOLKEY specific INS values (public) */
#define COOLKEY_INS_GET_LIFE_CYCLE             0xf2
#define COOLKEY_INS_GET_STATUS                 0x3c
#define COOLKEY_INS_VERIFY_PIN                 0x42
#define COOLKEY_INS_LIST_OBJECTS               0x58

/* COOLKEY specific INS values (require nonce) */
#define COOLKEY_INS_COMPUTE_CRYPT              0x36
#define COOLKEY_INS_COMPUTE_ECC_KEY_AGREEMENT  0x37
#define COOLKEY_INS_COMPUTE_ECC_SIGNATURE      0x38
#define COOLKEY_INS_GET_RANDOM                 0x72
#define COOLKEY_INS_READ_OBJECT                0x56
#define COOLKEY_INS_WRITE_OBJECT               0x54
#define COOLKEY_INS_LOGOUT                     0x61

/* COMPUTE_CRYPT and COMPUT_ECC parameters */
#define COOLKEY_CRYPT_INIT     1
#define COOLKEY_CRYPT_PROCESS  2
#define COOLKEY_CRYPT_FINAL    3
#define COOLKEY_CRYPT_ONE_STEP 4

#define COOLKEY_CRYPT_MODE_RSA_NO_PAD    0x00
#define COOLKEY_CRYPT_LOCATION_APDU      0x01
#define COOLKEY_CRYPT_LOCATION_DL_OBJECT 0x02
#define COOLKEY_CRYPT_DIRECTION_ENCRYPT  0x03

/* List Objects parameters */
#define COOLKEY_LIST_RESET 0x00
#define COOLKEY_LIST_NEXT  0x01

/* Special object identifiers */
#define COOLKEY_DL_OBJECT_ID       0xffffffff
#define COOLKEY_COMBINED_OBJECT_ID 0x7a300000 /* 'z0\0\0' */
#define COOLKEY_INVALID_KEY        0xff00
#define COOLKEY_KEY_CLASS			'k'
#define COOLKEY_NONCE_SIZE  8

/* returned from the coolkey extended life cycle apdu */
typedef struct coolkey_life_cycle {
	u8 life_cycle;
	u8 pin_count;
	u8 protocol_version_major;
	u8 protocol_version_minor;
} coolkey_life_cycle_t;

/* return by the coolkey status apdu */
typedef struct coolkey_status {
	u8 protocol_version_major;
	u8 protocol_version_minor;
	u8 applet_major_version;
	u8 applet_minor_version;
	u8 total_object_memory[4];
	u8 free_object_memory[4];
	u8 pin_count;
	u8 key_count;
	u8 logged_in_identities[2];
} coolkey_status_t;

/* format of the coolkey_cuid, either constructed from cplc data or read from the combined object */
typedef struct coolkey_cuid {
	u8 ic_fabricator[2];
	u8 ic_type[2];
	u8 ic_batch[2];
	u8 ic_serial_number[4];
} coolkey_cuid_t;

/* parameter for list objects apdu */
typedef struct coolkey_object_info {
	u8 object_id[4];
	u8 object_length[4];
	u8 read_acl[2];
	u8 write_acl[2];
	u8 delete_acl[2];
} coolkey_object_info_t;

/* parameter for the read object apdu */
typedef struct coolkey_read_object_param {
	u8 object_id[4];
	u8 offset[4];
	u8 length;
} coolkey_read_object_param_t;

/* parameter for the write object apdu */
typedef struct coolkey_write_object_param {
	coolkey_read_object_param_t head;
	u8 buf[COOLKEY_MAX_CHUNK_SIZE];
} coolkey_write_object_param_t;

/* coolkey uses muscle like objects, but when coolkey is managed by the TPS system
 * it creates a single object and encodes the individual objects inside the
 * common single object. This allows more efficient reading of all the objects
 * (because we can use a single apdu call and we can compress all the objects
 * together and take advantage of the fact that many of the certs share the same subject and issue). */
typedef struct coolkey_combined_header {
	u8	format_version[2];
	u8	object_version[2];
	coolkey_cuid_t cuid;
	u8	compression_type[2];
	u8	compression_length[2];
	u8	compression_offset[2];
} coolkey_combined_header_t;

#define COOLKEY_COMPRESSION_NONE 0
#define COOLKEY_COMPRESSION_ZLIB 1

/*
 * This is the header of the decompressed portion of the combined object
 */
typedef struct coolkey_decompressed_header {
	u8 object_offset[2];
	u8 object_count[2];
	u8 token_name_length;
	u8 token_name[255];      /* arbitrary size up to token_name_length */
} coolkey_decompressed_header_t;

/*
 * header for an object. There are 2 types of object headers, v1 and v0.
 * v1 is the most common, and is always found in a combined object, so
 * we only specify the v0 in the name of the structure.
 */

typedef struct coolkey_v0_object_header {
	u8 record_type;				 /* version 0 or version 1 */
	u8 object_id[4]; 			 /*  coolkey object id  */
	u8 attribute_data_len[2];    /* the length in bytes of the next block of
								  * attribute records */
	/* followed by the first attribute record */
} coolkey_v0_object_header_t;

typedef struct coolkey_v0_attribute_header {
	u8 attribute_attr_type[4];	/* CKA_ATTRIBUTE_TYPE */
	u8 attribute_data_len[2];	/* Length of the attribute */
	/* followed by the actual attribute data */
} coolkey_v0_attribute_header_t;

/* combined objects are v1 objects without the record_type indicator */
typedef struct coolkey_combined_object_header {
	u8 object_id[4]; 			 /*  coolkey object id  */
	u8 fixed_attributes_values[4]; /* compressed fixed attributes */
	u8 attribute_count[2];		/* the number of attribute records that follow */
	/* followed by the first attribute */
} coolkey_combined_object_header_t;

typedef struct coolkey_object_header {
	u8 record_type;				/* version 0 or version 1 */
	u8 object_id[4]; 			 /*  coolkey object id  */
	u8 fixed_attributes_values[4]; /* compressed fixed attributes */
	u8 attribute_count[2];		/* the number of attribute records that follow */
	/* followed by the first attribute */
} coolkey_object_header_t;

#define COOLKEY_V0_OBJECT 0
#define COOLKEY_V1_OBJECT 1

/* vi attribute header */
typedef struct coolkey_attribute_header {
	u8 attribute_attr_type[4]; /* CKA_ATTRIBUTE_TYPE */
	u8 attribute_data_type;    /* the Type of data stored */
	/* optional attribute data, or attribute len+data, depending on the value of data_type */
} coolkey_attribute_header_t;

/* values for attribute_data_type */
#define COOLKEY_ATTR_TYPE_STRING      0
#define COOLKEY_ATTR_TYPE_INTEGER     1
#define COOLKEY_ATTR_TYPE_BOOL_FALSE  2
#define COOLKEY_ATTR_TYPE_BOOL_TRUE   3

/*
 * format of the fix_attribute values. These are stored as a big endian uint32_t with the below bit field
 * Definitions:
 *
struct coolkey_fixed_attributes_values {
	uint32_t  cka_id:4;
	uint32_t  cka_class:3;
	uint32_t  cka_token:1;
	uint32_t  cka_private:1;
	uint32_t  cka_modifiable:1;
	uint32_t  cka_derive:1;
	uint32_t  cka_local:1;
	uint32_t  cka_encrypt:1;
	uint32_t  cka_decrypt:1;
	uint32_t  cka_wrap:1;
	uint32_t  cka_unwrap:1;
	uint32_t  cka_sign:1;
	uint32_t  cka_sign_recover:1;
	uint32_t  cka_verify:1;
	uint32_t  cka_verify_recover:1;
	uint32_t  cka_sensitive:1;
	uint32_t  cka_always_sensitive:1;
	uint32_t  cka_extractable:1;
	uint32_t  cka_never_extractable:1;
	uint32_t  reserved:8;
};

 *  cka_class is used to determine which booleans are valid. Any attributes in the full attribute list
 *  takes precedence over the fixed attributes. That is if there is a CKA_ID in the full attribute list,
 *  The cka_id in the fixed_attributes is ignored. When determining which boolean attribute is valid, the
 *  cka_class in the fixed attributes are used, even if it is overridden by the  full attribute list.
 * valid cka_class values and their corresponding valid bools are as follows:
 *
 *     0 CKO_DATA                          cka_private, cka_modifiable, cka_token
 *     1 CKO_CERTIFICATE                   cka_private, cka_modifiable, cka_token
 *     2 CKO_PUBLIC_KEY                    cka_private, cka_modifiable, cka_token
 *                                         cka_derive, cka_local, cka_encrypt, cka_wrap
 *                                         cka_verify, cka_verify_recover
 *     3 CKO_PRIVATE_KEY                   cka_private, cka_modifiable, cka_token
 *                                         cka_derive, cka_local, cka_decrypt, cka_unwrap
 *                                         cka_sign, cka_sign_recover, cka_sensitive,
 *                                         cka_always_sensitive, cka_extractable,
 *                                         cka_never_extractable
 *     4 CKO_SECRET_KEY                    cka_private, cka_modifiable, cka_token
 *                                         cka_derive, cka_local, cka_encrypt, cka_decrypt,
 *                                         cka_wrap, cka_unwrap, cka_sign, cka_verify,
 *                                         cka_sensitive, cka_always_sensitive,
 *                                         cka_extractable, cka_never_extractable
 *     5-7 RESERVED                        none
 *
 */

/*
 * Coolkey attribute record handling functions.
 */

/* get the length of the attribute from a V1 attribute header. If encoded_len == true, then return the length of
 * the attribute data field (including any explicit length values, If encoded_len = false return the length of
 * the actual attribute data.
 */
static int
coolkey_v1_get_attribute_len(const u8 *attr, size_t buf_len, size_t *len, int encoded_len)
{
	coolkey_attribute_header_t *attribute_head = (coolkey_attribute_header_t *)attr;

	*len = 0;
	/* don't reference beyond our buffer */
	if (buf_len < sizeof(coolkey_attribute_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	switch (attribute_head->attribute_data_type) {
	case COOLKEY_ATTR_TYPE_STRING:
		if (buf_len < (sizeof(coolkey_attribute_header_t) +2)) {
			break;
		}
		*len = bebytes2ushort(attr + sizeof(coolkey_attribute_header_t));
		if (encoded_len) {
			*len += 2;
		}
		return SC_SUCCESS;
	case COOLKEY_ATTR_TYPE_BOOL_FALSE:
	case COOLKEY_ATTR_TYPE_BOOL_TRUE:
		/* NOTE: there is no encoded data from TYPE_BOOL_XXX, so we return length 0, but the length
		 * of the attribute is actually 1 byte, so if encoded_len == false, return 1 */
		*len = encoded_len ? 0: 1;
		return SC_SUCCESS;
		break;
	case COOLKEY_ATTR_TYPE_INTEGER:
		*len = 4; /* length is 4 in both encoded length and attribute length */
		return SC_SUCCESS;
	default:
		break;
	}
	return SC_ERROR_CORRUPTED_DATA;
}

/* length of the attribute data is stored in the header of the v0 record */
static int
coolkey_v0_get_attribute_len(const u8 *attr, size_t buf_len, size_t *len)
{
	coolkey_v0_attribute_header_t *attribute_head = (coolkey_v0_attribute_header_t *)attr;
	/* don't reference beyond our buffer */
	if (buf_len < sizeof(coolkey_v0_attribute_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	*len = bebytes2ushort(attribute_head->attribute_data_len);
	return SC_SUCCESS;
}

/* these next 3 functions gets the length of the full attribute record, including
 * the attribute header */
static size_t
coolkey_v1_get_attribute_record_len(const u8 *attr, size_t buf_len)
{
	size_t attribute_len = sizeof(coolkey_attribute_header_t);
	size_t len = 0;
	int r;

	r = coolkey_v1_get_attribute_len(attr, buf_len, &len, 1);
	if (r < 0) {
		return buf_len; /* skip to the end, ignore the rest of the record */
	}

	return MIN(buf_len,attribute_len+len);
}


static size_t
coolkey_v0_get_attribute_record_len(const u8 *attr, size_t buf_len)
{
	size_t attribute_len = sizeof(coolkey_v0_attribute_header_t);
	size_t len;
	int r;

	r = coolkey_v0_get_attribute_len(attr, buf_len, &len);
	if (r < 0) {
		return buf_len; /* skip to the end, ignore the rest of the record */
	}
	return MIN(buf_len,attribute_len+len);
}

static size_t
coolkey_get_attribute_record_len(const u8 *attr, u8 obj_record_type, size_t buf_len)
{
	if (obj_record_type ==  COOLKEY_V0_OBJECT) {
		return coolkey_v0_get_attribute_record_len(attr, buf_len);
	}
	if (obj_record_type != COOLKEY_V1_OBJECT) {
		return buf_len; /* skip to the end */
	}
	return coolkey_v1_get_attribute_record_len(attr, buf_len);
}

/*
 * Attribute type shows up in the same place in all attribute record types. Carry record_type in case
 * this changes in the future.
 */
static CK_ATTRIBUTE_TYPE
coolkey_get_attribute_type(const u8 *attr, u8 obj_record_type, size_t buf_len)
{
	coolkey_attribute_header_t *attribute_header = (coolkey_attribute_header_t *) attr;

	return bebytes2ulong(attribute_header->attribute_attr_type);
}

/*
 * return the start of the attribute section based on the record type
 */
static const u8 *
coolkey_attribute_start(const u8 *obj, u8 object_record_type, size_t buf_len)
{
	size_t offset = object_record_type == COOLKEY_V1_OBJECT ? sizeof(coolkey_object_header_t) :
			sizeof(coolkey_v0_object_header_t);

	if ((object_record_type != COOLKEY_V1_OBJECT) && (object_record_type != COOLKEY_V0_OBJECT)) {
		return NULL;
	}
	if (offset > buf_len) {
		return NULL;
	}
	return obj + offset;
}

/*
 * We don't have the count in the header for v0 attributes,
 * Count them.
 */
static int
coolkey_v0_get_attribute_count(const u8 *obj, size_t buf_len)
{
	coolkey_v0_object_header_t *object_head = (coolkey_v0_object_header_t *)obj;
	const u8 *attr;
	int count = 0;
	size_t attribute_data_len;

	/* make sure we have enough of the object to read the record_type */
	if (buf_len <= sizeof(coolkey_v0_object_header_t)) {
		return 0;
	}
	/*
	 * now loop through all the attributes in the list. first find the start of the list
	 */
	attr = coolkey_attribute_start(obj, COOLKEY_V0_OBJECT, buf_len);
	if (attr == NULL) {
		return 0;
	}

	buf_len -= (attr-obj);
	attribute_data_len = bebytes2ushort(object_head->attribute_data_len);
	if (buf_len < attribute_data_len) {
		return 0;
	}

	while (attribute_data_len) {
		size_t len = coolkey_v0_get_attribute_record_len(attr, buf_len);

		if (len == 0) {
			break;
		}
		/*  This is an error in the token data, don't parse the last attribute */
		if (len > attribute_data_len) {
			break;
		}
		/* we know that coolkey_v0_get_attribute_record_len never
		 * 	returns more than buf_len, so we can safely assert that.
		 * 	If the assert is true, you can easily see that the loop
		 * 	will eventually break with len == 0, even if attribute_data_len
		 * 	was invalid */
		assert(len <= buf_len);
		count++;
		attr += len;
		buf_len -= len;
		attribute_data_len -= len;
	}
	return count;
}

static int
coolkey_v1_get_attribute_count(const u8 *obj, size_t buf_len)
{
	coolkey_object_header_t *object_head = (coolkey_object_header_t *)obj;

	if (buf_len <= sizeof(coolkey_object_header_t)) {
		return 0;
	}
	return bebytes2ushort(object_head->attribute_count);
}

static int
coolkey_get_attribute_count(const u8 *obj, u8 object_record_type, size_t buf_len)
{
	if (object_record_type == COOLKEY_V0_OBJECT) {
		return coolkey_v0_get_attribute_count(obj, buf_len);
	}
	if (object_record_type != COOLKEY_V1_OBJECT) {
		return 0;
	}
	return coolkey_v1_get_attribute_count(obj, buf_len);
}

/*
 * The next three functions return a parsed attribute value from an attribute record.
 */
static int
coolkey_v0_get_attribute_data(const u8 *attr, size_t buf_len, sc_cardctl_coolkey_attribute_t *attr_out)
{
	/* we need to manually detect types CK_ULONG */
	CK_ATTRIBUTE_TYPE attr_type = coolkey_get_attribute_type(attr, COOLKEY_V0_OBJECT, buf_len);
	int r;
	size_t len;

	attr_out->attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_STRING;
	attr_out->attribute_length = 0;
	attr_out->attribute_value = NULL;

	r = coolkey_v0_get_attribute_len(attr, buf_len, &len);
	if (r < 0) {
		return r;
	}
	if (len + sizeof(coolkey_v0_attribute_header_t) > buf_len) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	if ((attr_type == CKA_CLASS) || (attr_type == CKA_CERTIFICATE_TYPE)
									 || (attr_type == CKA_KEY_TYPE)) {
		if (len != 4) {
			return SC_ERROR_CORRUPTED_DATA;
		}
		attr_out->attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG;
	}
	/* return the length and the data */
	attr_out->attribute_length = len;
	attr_out->attribute_value = attr + sizeof(coolkey_v0_attribute_header_t);
	return SC_SUCCESS;
}

static u8 coolkey_static_false = CK_FALSE;
static u8 coolkey_static_true = CK_TRUE;

static int
coolkey_v1_get_attribute_data(const u8 *attr, size_t buf_len, sc_cardctl_coolkey_attribute_t *attr_out)
{
	int r;
	size_t len;
	coolkey_attribute_header_t *attribute_head = (coolkey_attribute_header_t *)attr;

	if (buf_len < sizeof(coolkey_attribute_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}

	/* we must have type V1. Process according to data type */
	switch (attribute_head->attribute_data_type) {
	/* ULONG has implied length of 4 */
	case COOLKEY_ATTR_TYPE_INTEGER:
		if (buf_len < (sizeof(coolkey_attribute_header_t) + 4)) {
			return SC_ERROR_CORRUPTED_DATA;
		}
		attr_out->attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG;
		attr_out->attribute_length = 4;
		attr_out->attribute_value = attr + sizeof(coolkey_attribute_header_t);
		return SC_SUCCESS;
	/* BOOL_FALSE and BOOL_TRUE have implied length and data */
	/* return type STRING for BOOLS */
	case COOLKEY_ATTR_TYPE_BOOL_FALSE:
		attr_out->attribute_length = 1;
		attr_out->attribute_value =  &coolkey_static_false;
		return SC_SUCCESS;
	case COOLKEY_ATTR_TYPE_BOOL_TRUE:
		attr_out->attribute_length = 1;
		attr_out->attribute_value =  &coolkey_static_true;
		return SC_SUCCESS;
	/* string type has encoded length */
	case COOLKEY_ATTR_TYPE_STRING:
		r = coolkey_v1_get_attribute_len(attr, buf_len, &len, 0);
		if (r < SC_SUCCESS) {
			return r;
		}
		if (buf_len < (len + sizeof(coolkey_attribute_header_t) + 2)) {
			return SC_ERROR_CORRUPTED_DATA;
		}
		attr_out->attribute_value = attr+sizeof(coolkey_attribute_header_t)+2;
		attr_out->attribute_length = len;
		return SC_SUCCESS;
	default:
		break;
	}
	return SC_ERROR_CORRUPTED_DATA;
}

int
coolkey_get_attribute_data(const u8 *attr, u8 object_record_type, size_t buf_len, sc_cardctl_coolkey_attribute_t *attr_out)
{
	/* handle the V0 objects first */
	if (object_record_type == COOLKEY_V0_OBJECT) {
		return coolkey_v0_get_attribute_data(attr, buf_len, attr_out);
	}

	/* don't crash if we encounter some new or corrupted coolkey device */
	if (object_record_type != COOLKEY_V1_OBJECT) {
		return SC_ERROR_NO_CARD_SUPPORT;
	}

	return coolkey_v1_get_attribute_data(attr, buf_len, attr_out);

}

/* convert an attribute type into a  bit in the fixed attribute uint32_t  */
static unsigned long
coolkey_get_fixed_boolean_bit(CK_ATTRIBUTE_TYPE type)
{
	switch(type) {
	case CKA_TOKEN:               return 0x00000080;
	case CKA_PRIVATE:             return 0x00000100;
	case CKA_MODIFIABLE:          return 0x00000200;
	case CKA_DERIVE:              return 0x00000400;
	case CKA_LOCAL:               return 0x00000800;
	case CKA_ENCRYPT:             return 0x00001000;
	case CKA_DECRYPT:             return 0x00002000;
	case CKA_WRAP:                return 0x00004000;
	case CKA_UNWRAP:              return 0x00008000;
	case CKA_SIGN:                return 0x00010000;
	case CKA_SIGN_RECOVER:        return 0x00020000;
	case CKA_VERIFY:              return 0x00040000;
	case CKA_VERIFY_RECOVER:      return 0x00080000;
	case CKA_SENSITIVE:           return 0x00100000;
	case CKA_ALWAYS_SENSITIVE:    return 0x00200000;
	case CKA_EXTRACTABLE:         return 0x00400000;
	case CKA_NEVER_EXTRACTABLE:   return 0x00800000;
	default: break;
	}
	return 0; /* return no bits */
}
/* This table lets us return a pointer to the CKA_ID value without allocating data or
 * creating a changeable static that could cause thread issues */
static const u8 coolkey_static_cka_id[16] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

/* This table provides the following:
 *     1) a mapping from a 3 bit cka_class to a full 32 bit CKA_CLASS_TYPE value we can return.
 *     2) the mask of valid boolean attributes in the fixed attributes.
 */
struct coolkey_fixed_class {
	u8 class_value[4];
	unsigned long boolean_mask;
};

static const struct coolkey_fixed_class coolkey_static_cka_class[8] = {
	{ { 0, 0, 0, 0}, 0x00000380 }, /* DATA */
	{ { 0, 0, 0, 1}, 0x00000380 }, /* CERTIFICATE */
	{ { 0, 0, 0, 2}, 0x000c5f80 }, /* PUBLIC_KEY */
	{ { 0, 0, 0, 3}, 0x00f3af80 }, /* PRIVATE_KEY */
	{ { 0, 0, 0, 4}, 0x00f5ff80 }, /* SECRET_KEY */
	{ { 0, 0, 0, 5}, 0x00000000 },
	{ { 0, 0, 0, 6}, 0x00000000 },
	{ { 0, 0, 0, 7}, 0x00000000 }
};

/*
 * handle fixed attributes (V1 only)
 */
static int
coolkey_get_attribute_data_fixed(CK_ATTRIBUTE_TYPE attr_type, unsigned long fixed_attributes,
																sc_cardctl_coolkey_attribute_t *attr_out) {
	unsigned long cka_id = fixed_attributes & 0xf;
	unsigned long cka_class = ((fixed_attributes) >> 4) & 0x7;
	unsigned long mask, bit;

	if (attr_type == CKA_ID) {
		attr_out->attribute_length = 1;
		attr_out->attribute_value= &coolkey_static_cka_id[cka_id];
		return SC_SUCCESS;
	}
	if (attr_type == CKA_CLASS) {
		attr_out->attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_ULONG;
		attr_out->attribute_length = 4;
		attr_out->attribute_value = coolkey_static_cka_class[cka_class].class_value;
		return SC_SUCCESS;
	}
	/* If it matched, it must be one of the booleans */
	mask = coolkey_static_cka_class[cka_class].boolean_mask;
	bit = coolkey_get_fixed_boolean_bit(attr_type);
	/* attribute isn't in the list */
	if ((bit & mask) == 0) {
		return SC_ERROR_DATA_OBJECT_NOT_FOUND;
	}
	attr_out->attribute_length = 1;
	attr_out->attribute_value = bit & fixed_attributes ? &coolkey_static_true : &coolkey_static_false;
	return SC_SUCCESS;
}



static int
coolkey_v1_get_object_length(u8 *obj, size_t buf_len)
{
	coolkey_combined_object_header_t *object_head = (coolkey_combined_object_header_t *) obj;
	int attribute_count;
	u8 *current_attribute;
	int j;
	size_t len;

	len = sizeof(coolkey_combined_object_header_t);
	if (buf_len <= len) {
		return buf_len;
	}
	attribute_count = bebytes2ushort(object_head->attribute_count);
	buf_len -= len;

	for (current_attribute = obj + len, j = 0; j < attribute_count; j++) {
		size_t attribute_len = coolkey_v1_get_attribute_record_len(current_attribute, buf_len);

		len += attribute_len;
		current_attribute += attribute_len;
		buf_len -= attribute_len;
	}
	return len;
}

/*
 * COOLKEY private data per card state
 */
typedef struct coolkey_private_data {
	u8 protocol_version_major;
	u8 protocol_version_minor;
	u8 format_version_major;
	u8 format_version_minor;
	unsigned short object_version;
	u8 life_cycle;
	u8 pin_count;
	u8 *token_name;				/* our token name read from the token */
	size_t token_name_length;		/* length of our token name */
	u8 nonce[COOLKEY_NONCE_SIZE];		/* nonce returned from login */
	int nonce_valid;
	coolkey_cuid_t cuid;			/* card unique ID from the CCC */
	sc_cardctl_coolkey_object_t *obj;	/* pointer to the current selected object */
	list_t objects_list;			/* list of objects on the token */
	unsigned short key_id;			/* key id set by select */
	int	algorithm;			/* saved from set_security_env */
	int operation;				/* saved from set_security_env */
} coolkey_private_data_t;

#define COOLKEY_DATA(card) ((coolkey_private_data_t*)card->drv_data)

int
coolkey_compare_id(const void * a, const void *b)
{
	if (a == NULL || b == NULL)
		return 1;
	return ((sc_cardctl_coolkey_object_t *)a)->id
	    != ((sc_cardctl_coolkey_object_t *)b)->id;
}

/* For SimCList autocopy, we need to know the size of the data elements */
size_t coolkey_list_meter(const void *el) {
	return sizeof(sc_cardctl_coolkey_object_t);
}

static void coolkey_free_private_data(coolkey_private_data_t *priv);

static coolkey_private_data_t *coolkey_new_private_data(void)
{
	coolkey_private_data_t *priv;

	/* allocate priv and zero all the fields */
	priv = calloc(1, sizeof(coolkey_private_data_t));
	if (!priv)
		return NULL;

	/* set other fields as appropriate */
	priv->key_id = COOLKEY_INVALID_KEY;
	if (list_init(&priv->objects_list) != 0 ||
	    list_attributes_comparator(&priv->objects_list, coolkey_compare_id) != 0 ||
	    list_attributes_copy(&priv->objects_list, coolkey_list_meter, 1) != 0) {
		coolkey_free_private_data(priv);
		return NULL;
	}

	return priv;
}

static void coolkey_free_private_data(coolkey_private_data_t *priv)
{
	list_t *l = &priv->objects_list;
	sc_cardctl_coolkey_object_t *o;

	/* Clean up the allocated memory in the items */
	list_iterator_start(l);
	while (list_iterator_hasnext(l)) {
		o = (sc_cardctl_coolkey_object_t *)list_iterator_next(l);
		free(o->data);
		o->data = NULL;
	}
	list_iterator_stop(l);

	list_destroy(&priv->objects_list);
	if (priv->token_name) {
		free(priv->token_name);
	}
	free(priv);
	return;
}

/*
 * Object list operations
 */
static int coolkey_add_object_to_list(list_t *list, const sc_cardctl_coolkey_object_t *object)
{
	if (list_append(list, object) < 0)
		return SC_ERROR_UNKNOWN;
	return SC_SUCCESS;
}

#define COOLKEY_AID "\xA0\x00\x00\x01\x16"
static sc_cardctl_coolkey_object_t *
coolkey_find_object_by_id(list_t *list, unsigned long object_id)
{
	int pos;
	static sc_cardctl_coolkey_object_t cmp = {{
		"", 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ COOLKEY_AID, sizeof(COOLKEY_AID)-1 }
	}, 0, 0, NULL};

	cmp.id = object_id;
	if ((pos = list_locate(list, &cmp)) < 0)
		return NULL;

	return list_get_at(list, pos);
}


static const sc_path_t coolkey_template_path = {
	"", 0, 0, 0, SC_PATH_TYPE_DF_NAME,
	{ COOLKEY_AID, sizeof(COOLKEY_AID)-1 }
};

struct coolkey_error_codes_st {
	int sc_error;
	char *description;
};

static const struct coolkey_error_codes_st coolkey_error_codes[]= {
	{SC_ERROR_UNKNOWN,                       "Reserved 0x9c00" },
	{SC_ERROR_NOT_ENOUGH_MEMORY,             "No memory left on card" },
	{SC_ERROR_PIN_CODE_INCORRECT,            "Authentication failed" },
	{SC_ERROR_NOT_ALLOWED,                   "Operation not allowed" },
	{SC_ERROR_UNKNOWN,                       "Reserved 0x9c04" },
	{SC_ERROR_NO_CARD_SUPPORT,               "Unsupported feature" },
	{SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Not authorized" },
	{SC_ERROR_DATA_OBJECT_NOT_FOUND,         "Object not found" },
	{SC_ERROR_FILE_ALREADY_EXISTS,           "Object exists" },
	{SC_ERROR_NO_CARD_SUPPORT,               "Incorrect Algorithm" },
	{SC_ERROR_UNKNOWN,                       "Reserved 0x9c0a" },
	{SC_ERROR_SM_INVALID_CHECKSUM,           "Signature invalid" },
	{SC_ERROR_AUTH_METHOD_BLOCKED,           "Identity blocked" },
	{SC_ERROR_UNKNOWN,                       "Reserved 0x9c0d" },
	{SC_ERROR_UNKNOWN,                       "Reserved 0x9c0e" },
	{SC_ERROR_INCORRECT_PARAMETERS,          "Invalid parameter" },
	{SC_ERROR_INCORRECT_PARAMETERS,          "Incorrect P1" },
	{SC_ERROR_INCORRECT_PARAMETERS,          "Incorrect P2" },
	{SC_ERROR_FILE_END_REACHED,              "Sequence End" },
};

static const unsigned int
coolkey_number_of_error_codes = sizeof(coolkey_error_codes)/sizeof(coolkey_error_codes[0]);

static int coolkey_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	sc_log(card->ctx, 
		"sw1 = 0x%02x, sw2 = 0x%02x\n", sw1, sw2);

	if (sw1 == 0x90 && sw2 == 0x00)
		return SC_SUCCESS;

	if (sw1 == 0x9c) {
		if (sw2 == 0xff) {
			/* shouldn't happen on a production applet, 0x9cff is a debugging error code */
			return SC_ERROR_INTERNAL;
		}
		if (sw2 >= coolkey_number_of_error_codes) {
			return SC_ERROR_UNKNOWN;
		}
		return coolkey_error_codes[sw2].sc_error;
	}

	/* iso error */
        return sc_get_iso7816_driver()->ops->check_sw(card, sw1, sw2);
}

/*
 * Send a command and receive data.
 *
 * A caller may provide a buffer, and length to read. If not provided,
 * an internal 4096 byte buffer is used, and a copy is returned to the
 * caller. that need to be freed by the caller.
 *
 * modelled after a similar function in card-piv.c. The coolkey version
 * adds the coolkey nonce to user authenticated operations.
 */

static int coolkey_apdu_io(sc_card_t *card, int cla, int ins, int p1, int p2,
	const u8 * sendbuf, size_t sendbuflen, u8 ** recvbuf, size_t * recvbuflen,
	const u8 *nonce, size_t nonce_len)
{
	int r;
	sc_apdu_t apdu;
	u8 rbufinitbuf[COOLKEY_MAX_SIZE];
	u8 rsendbuf[COOLKEY_MAX_SIZE];
	u8 *rbuf;
	size_t rbuflen;
	int cse = 0;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, 
		 "%02x %02x %02x %"SC_FORMAT_LEN_SIZE_T"u : %"SC_FORMAT_LEN_SIZE_T"u %"SC_FORMAT_LEN_SIZE_T"u\n",
		 ins, p1, p2, sendbuflen, card->max_send_size,
		 card->max_recv_size);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	/* if caller provided a buffer and length */
	if (recvbuf && *recvbuf && recvbuflen && *recvbuflen) {
		rbuf = *recvbuf;
		rbuflen = *recvbuflen;
	}

	if (sendbuf || nonce) {
		if (recvbuf) {
			cse = SC_APDU_CASE_4_SHORT;
		} else {
			cse = SC_APDU_CASE_3_SHORT;
		}
	} else {
		if (recvbuf) {
			cse = SC_APDU_CASE_2_SHORT;
		} else {
			cse = SC_APDU_CASE_1;
		}
	}

	/* append the nonce if we have it. Coolkey just blindly puts this at the end
	 * of the APDU (while adjusting lc). This converts case 1 to case 3. coolkey
	 * also always drops le in case 4 (which happens when proto = T0). nonces are
	 * never used on case 2 commands, so we can simply append the nonce to the data
	 * and we should be fine */
	if (nonce) {
		u8 *buf = rsendbuf;
		if (sendbuf) {
			sendbuflen = MIN(sendbuflen,sizeof(rsendbuf)-nonce_len);
			memcpy(rsendbuf, sendbuf, sendbuflen);
			buf += sendbuflen;
		}
		memcpy(buf, nonce, nonce_len);
		sendbuflen += nonce_len;
		sendbuf =rsendbuf;
	}

	sc_format_apdu(card, &apdu, cse, ins, p1, p2);

	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;


	/* coolkey uses non-standard classes */
	apdu.cla = cla;

	if (recvbuf) {
		apdu.resp = rbuf;
		apdu.le = (rbuflen > 255) ? 255 : rbuflen;
		apdu.resplen = rbuflen;
	} else {
		 apdu.resp =  rbuf;
		 apdu.le = 0;
		 apdu.resplen = 0;
	}

	sc_log(card->ctx, 
		 "calling sc_transmit_apdu flags=%lx le=%"SC_FORMAT_LEN_SIZE_T"u, resplen=%"SC_FORMAT_LEN_SIZE_T"u, resp=%p",
		 apdu.flags, apdu.le, apdu.resplen, apdu.resp);

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	sc_log(card->ctx, 
		 "result r=%d apdu.resplen=%"SC_FORMAT_LEN_SIZE_T"u sw1=%02x sw2=%02x",
		 r, apdu.resplen, apdu.sw1, apdu.sw2);

	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}

	if (recvbuflen) {
		if (recvbuf && *recvbuf == NULL) {
			*recvbuf =  malloc(apdu.resplen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			memcpy(*recvbuf, rbuf, apdu.resplen);
		}
		*recvbuflen =  apdu.resplen;
		r = *recvbuflen;
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Helpers to handle coolkey commands
 */
static int
coolkey_get_life_cycle(sc_card_t *card, coolkey_life_cycle_t *life_cycle)
{
	coolkey_status_t status;
	u8 *receive_buf;
	size_t receive_len;
	int len;

	receive_len = sizeof(*life_cycle);
	receive_buf = (u8 *)life_cycle;
	len = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_GET_LIFE_CYCLE, 0, 0,
			NULL, 0, &receive_buf, &receive_len, NULL, 0);
	if (len == sizeof(*life_cycle)) {
		return SC_SUCCESS;
	}

	receive_len = 1;
	receive_buf = &life_cycle->life_cycle;
	len = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_GET_LIFE_CYCLE, 0, 0,
			NULL, 0, &receive_buf, &receive_len, NULL, 0);
	if (len < 0) { /* Error from the trasmittion */
		return len;
	}
	if (len != 1) { /* The returned data is invalid */
		return SC_ERROR_INTERNAL;
	}
	receive_len = sizeof(status);
	receive_buf = (u8 *)&status;
	len = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_GET_STATUS, 0, 0,
			NULL, 0, &receive_buf, &receive_len, NULL, 0);
	if (len < 0) { /* Error from the trasmittion */
		return len;
	}
	if (len != sizeof(status)) { /* The returned data is invalid */
		return SC_ERROR_INTERNAL;
	}
	life_cycle->protocol_version_major = status.protocol_version_major;
	life_cycle->protocol_version_minor = status.protocol_version_minor;
	life_cycle->pin_count = status.pin_count;
	return SC_SUCCESS;
}

/* select the coolkey applet */
static int coolkey_select_applet(sc_card_t *card)
{
	u8 aid[] = { 0x62, 0x76, 0x01, 0xff, 0x00, 0x00, 0x00 };
	return coolkey_apdu_io(card, ISO7816_CLASS, ISO7816_INS_SELECT_FILE, 4, 0,
			&aid[0], sizeof(aid), NULL, NULL,  NULL, 0);
}

static void
coolkey_make_cuid_from_cplc(coolkey_cuid_t *cuid, global_platform_cplc_data_t *cplc_data)
{
	cuid->ic_fabricator[0]    = cplc_data->ic_fabricator[0];
	cuid->ic_fabricator[1]    = cplc_data->ic_fabricator[1];
	cuid->ic_type[0]          = cplc_data->ic_type[0];
	cuid->ic_type[1]          = cplc_data->ic_type[1];
	cuid->ic_batch[0]         = cplc_data->ic_batch[0];
	cuid->ic_batch[1]         = cplc_data->ic_batch[1];
	cuid->ic_serial_number[0] = cplc_data->ic_serial_number[0];
	cuid->ic_serial_number[1] = cplc_data->ic_serial_number[1];
	cuid->ic_serial_number[2] = cplc_data->ic_serial_number[2];
	cuid->ic_serial_number[3] = cplc_data->ic_serial_number[3];
}

/*
 * Read a COOLKEY coolkey object.
 */
static int coolkey_read_object(sc_card_t *card, unsigned long object_id, size_t offset,
			u8 *out_buf, size_t out_len, u8 *nonce, size_t nonce_size)
{
	coolkey_read_object_param_t params;
	u8 *out_ptr;
	size_t left = 0;
	size_t len;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	ulong2bebytes(&params.object_id[0], object_id);

	out_ptr = out_buf;
	left = out_len;
	do {
		ulong2bebytes(&params.offset[0], offset);
		params.length = MIN(left, COOLKEY_MAX_CHUNK_SIZE);
		len = left;
		r = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_READ_OBJECT, 0, 0,
			(u8 *)&params, sizeof(params), &out_ptr, &len, nonce, nonce_size);
		if (r < 0) {
			goto fail;
		}
		/* sanity check to make sure we don't overflow left */
		if ((left < len) || (len == 0)) {
			r = SC_ERROR_INTERNAL;
			goto fail;
		}
		out_ptr += len;
		offset += len;
		left -= len;
	} while (left != 0);

	return out_len;

fail:
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Write a COOLKEY coolkey object.
 */
static int coolkey_write_object(sc_card_t *card, unsigned long object_id,
			size_t offset, const u8 *buf, size_t buf_len, const u8 *nonce, size_t nonce_size)
{
	coolkey_write_object_param_t params;
	size_t operation_len;
	size_t left = buf_len;
	int r;
	size_t max_operation_len;

	/* set limit for the card's maximum send size and short write */
	max_operation_len = MIN(COOLKEY_MAX_CHUNK_SIZE, (card->max_send_size - sizeof(coolkey_read_object_param_t) - nonce_size));

	ulong2bebytes(&params.head.object_id[0], object_id);

	do {
		ulong2bebytes(&params.head.offset[0], offset);
		operation_len = MIN(left, max_operation_len);
		params.head.length = operation_len;
		memcpy(params.buf, buf, operation_len);
		r = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_WRITE_OBJECT, 0, 0,
			(u8 *)&params, sizeof(params.head)+operation_len, NULL, 0, nonce, nonce_size);
		if (r < 0) {
			goto fail;
		}
		buf += operation_len;
		offset += operation_len;
		left -= operation_len;
	} while (left != 0);

	return buf_len - left;

fail:
	return r;
}

/*
 * coolkey_read_binary will read a coolkey object off the card. That object is selected
 * by select file. If we've already read the object, we'll return the data from the cache.
 * coolkey objects are encoded PKCS #11 entries, not pkcs #15 data. pkcs15-coolkey will
 * translate the objects into their PKCS #15 equivalent data structures.
 */
static int coolkey_read_binary(sc_card_t *card, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	int r = 0, len;
	u8 *data = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (idx > priv->obj->length) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_END_REACHED);
	}

	/* if we've already read the data, just return it */
	if (priv->obj->data) {
		sc_log(card->ctx, 
			 "returning cached value idx=%u count=%"SC_FORMAT_LEN_SIZE_T"u",
			 idx, count);
		len = MIN(count, priv->obj->length-idx);
		memcpy(buf, &priv->obj->data[idx], len);
		LOG_FUNC_RETURN(card->ctx, len);
	}

	sc_log(card->ctx, 
		 "clearing cache idx=%u count=%"SC_FORMAT_LEN_SIZE_T"u",
		 idx, count);

	data = malloc(priv->obj->length);
	if (data == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto done;
	}


	r = coolkey_read_object(card, priv->obj->id, 0, data, priv->obj->length,
		priv->nonce, sizeof(priv->nonce));
	if (r < 0)
		goto done;

	if ((size_t) r != priv->obj->length) {
		priv->obj->length = r;
	}


	/* OK we've read the data, now copy the required portion out to the callers buffer */
	len = MIN(count, priv->obj->length-idx);
	memcpy(buf, &data[idx], len);
	r = len;
	/* cache the data in the object */
	priv->obj->data=data;
	data = NULL;

done:
	if (data)
		free(data);
	LOG_FUNC_RETURN(card->ctx, r);
}

/* COOLKEY driver is read only. NOTE: The applet supports w/r operations, so it's perfectly
 * reasonable to try to create new objects, but currently TPS does not create applets
 * That allow user created objects, so this is a nice 2.0 feature. */
static int coolkey_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

/* initialize getting a list and return the number of elements in the list */
static int coolkey_get_init_and_get_count(list_t *list, int *countp)
{
	*countp = list_size(list);
	list_iterator_start(list);
	return SC_SUCCESS;
}

/* fill in the obj_info for the current object on the list and advance to the next object */
static int coolkey_fetch_object(list_t *list, sc_cardctl_coolkey_object_t *coolkey_obj)
{
	sc_cardctl_coolkey_object_t *ptr;
	if (!list_iterator_hasnext(list)) {
		return SC_ERROR_FILE_END_REACHED;
	}

	ptr = list_iterator_next(list);
	*coolkey_obj = *ptr;
	return SC_SUCCESS;
}

/* Finalize iterator */
static int coolkey_final_iterator(list_t *list)
{
	list_iterator_stop(list);
	return SC_SUCCESS;
}

static char * coolkey_cuid_to_string(coolkey_cuid_t *cuid)
{
	char *buf;
	size_t len = sizeof(coolkey_cuid_t)*2 + 1;
	buf = malloc(len);
	if (buf == NULL) {
		return NULL;
	}
	sc_bin_to_hex((u8 *)cuid, sizeof(*cuid), buf, len, 0);
	return buf;
}

static const struct manufacturer_list_st {
	unsigned short id;
	char *string;
} manufacturer_list[] = {
	{ 0x2050, "%04x Oberthur" },
	{ 0x4090, "%04x GemAlto (Infineon)" },
	{ 0x4780, "%04x STMicroElectronics" },
	{ 0x4780, "%04x RSA" },
	{ 0x534e, "%04x SafeNet" },
};

int manufacturer_list_count = sizeof(manufacturer_list)/sizeof(manufacturer_list[0]);

static char * coolkey_get_manufacturer(coolkey_cuid_t *cuid)
{
	unsigned short fabricator = bebytes2ushort(cuid->ic_fabricator);
	int i;
	char *buf;
	const char *manufacturer_string = "%04x Unknown";
	size_t len;
	int r;

	for (i=0; i < manufacturer_list_count; i++) {
		if (manufacturer_list[i].id == fabricator) {
			manufacturer_string = manufacturer_list[i].string;
			break;
		}
	}
	len = strlen(manufacturer_string)+1;
	buf= malloc(len);
	if (buf == NULL) {
		return NULL;
	}
	r = snprintf(buf, len, manufacturer_string, fabricator);
	if (r < 0) {
		free(buf);
		return NULL;
	}
	return buf;
}


static int coolkey_get_token_info(sc_card_t *card, sc_pkcs15_tokeninfo_t * token_info)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	char *label = NULL;
	char *manufacturer_id = NULL;
	char *serial_number = NULL;

	LOG_FUNC_CALLED(card->ctx);
	label = strdup((char *)priv->token_name);
	manufacturer_id = coolkey_get_manufacturer(&priv->cuid);
	serial_number = coolkey_cuid_to_string(&priv->cuid);

	if (label && manufacturer_id && serial_number) {
		token_info->label = label;
		token_info->manufacturer_id = manufacturer_id;
		token_info->serial_number = serial_number;
		return SC_SUCCESS;
	}
	free(label);
	free(manufacturer_id);
	free(serial_number);
	return SC_ERROR_OUT_OF_MEMORY;
}

static int coolkey_get_serial_nr_from_CUID(sc_card_t* card, sc_serial_number_t* serial)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);

	LOG_FUNC_CALLED(card->ctx);
	memcpy(serial->value, &priv->cuid, sizeof(priv->cuid));
	serial->len = sizeof(priv->cuid);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int
coolkey_fill_object(sc_card_t *card, sc_cardctl_coolkey_object_t *obj)
{
	int r;
	size_t buf_len = obj->length;
	u8 *new_obj_data = NULL;
	sc_cardctl_coolkey_object_t *obj_entry;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (obj->data != NULL) {
		return SC_SUCCESS;
	}
	new_obj_data = malloc(buf_len);
	if (new_obj_data == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
	r = coolkey_read_object(card, obj->id, 0, new_obj_data, buf_len,
				priv->nonce, sizeof(priv->nonce));
	if (r != (int)buf_len) {
		free(new_obj_data);
		if (r < 0) {
			LOG_FUNC_RETURN(card->ctx, r);
		}
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_CORRUPTED_DATA);
	}
	obj_entry = coolkey_find_object_by_id(&priv->objects_list, obj->id);
	if (obj_entry == NULL) {
		free(new_obj_data);
		return SC_ERROR_INTERNAL; /* shouldn't happen */
	}
	if (obj_entry->data != NULL) {
		free(new_obj_data);
		return SC_ERROR_INTERNAL; /* shouldn't happen */
	}
	/* Make sure we will not go over the allocated limits in the other
	 * objects if they somehow got different lengths in matching objects */
	if (obj_entry->length != obj->length) {
		free(new_obj_data);
		return SC_ERROR_INTERNAL; /* shouldn't happen */
	}
	obj_entry->data = new_obj_data;
	obj->data = new_obj_data;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * return a parsed record for the attribute which includes value, type, and length.
 * Handled both v1 and v0 record types. determine record type from the object.
 *  make sure we don't overrun the buffer if the token gives us bad data.
 */
static int
coolkey_find_attribute(sc_card_t *card, sc_cardctl_coolkey_attribute_t *attribute)
{
	u8 object_record_type;
	CK_ATTRIBUTE_TYPE attr_type = attribute->attribute_type;
	const u8 *obj = attribute->object->data;
	const u8 *attr = NULL;
	size_t buf_len = attribute->object->length;
	coolkey_object_header_t *object_head;
	int attribute_count,i;
	attribute->attribute_data_type = SC_CARDCTL_COOLKEY_ATTR_TYPE_STRING;
	attribute->attribute_length = 0;
	attribute->attribute_value = NULL;

	LOG_FUNC_CALLED(card->ctx);

	if (obj == NULL) {
		/* cast away const so we can cache the data value */
		int r = coolkey_fill_object(card, (sc_cardctl_coolkey_object_t *)attribute->object);
		if (r < 0) {
			return r;
		}
		obj = attribute->object->data;
		if (obj == NULL) {
			return SC_ERROR_INTERNAL;
		}
	}

	/* should be a static assert so we catch this at compile time */
	assert(sizeof(coolkey_object_header_t) >= sizeof(coolkey_v0_object_header_t));
	/* make sure we have enough of the object to read the record_type */
	if (buf_len <= sizeof(coolkey_v0_object_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	object_head = (coolkey_object_header_t *)obj;
	object_record_type = object_head->record_type;
	/* make sure it's a type we recognize */
	if ((object_record_type != COOLKEY_V1_OBJECT) && (object_record_type != COOLKEY_V0_OBJECT)) {
		return SC_ERROR_CORRUPTED_DATA;
	}

	/*
	 * now loop through all the attributes in the list. first find the start of the list
	 */
	attr = coolkey_attribute_start(obj, object_record_type, buf_len);
	if (attr == NULL) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	buf_len -= (attr-obj);

	/* now get the count */
	attribute_count = coolkey_get_attribute_count(obj, object_record_type, buf_len);
	for (i=0; i < attribute_count; i++) {
		size_t record_len = coolkey_get_attribute_record_len(attr, object_record_type, buf_len);
		/* make sure we have the complete record */
		if (buf_len < record_len || record_len < 4) {
			return SC_ERROR_CORRUPTED_DATA;
		}
		/* does the attribute match the one we are looking for */
		if (attr_type == coolkey_get_attribute_type(attr, object_record_type, record_len)) {
			/* yup, return it */
			return coolkey_get_attribute_data(attr, object_record_type, record_len, attribute);
		}
		/* go to the next attribute on the list */
		buf_len -= record_len;
		attr += record_len;
	}
	/* not find in attribute list, check the fixed attribute record */
	if (object_record_type == COOLKEY_V1_OBJECT) {
		unsigned long fixed_attributes = bebytes2ulong(object_head->fixed_attributes_values);

		return coolkey_get_attribute_data_fixed(attr_type, fixed_attributes, attribute);
	}
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND);
}

/*
 * pkcs 15 needs to find the cert matching the keys to fill in some of the fields that wasn't stored
 * with the key. To do this we need to look for the cert matching the key's CKA_ID. For flexibility,
 * We simply search using a pkcs #11 style template using the cardctl_coolkey_attribute_t structure */
sc_cardctl_coolkey_object_t *
coolkey_find_object_by_template(sc_card_t *card, sc_cardctl_coolkey_attribute_t *template, int count)
{
	list_t *list;
	sc_cardctl_coolkey_object_t *current, *rv = NULL;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	int i, r;
	unsigned int tmp_pos = (unsigned int) -1;

	list = &priv->objects_list;
	if (list->iter_active) {
		/* workaround missing functionality of second iterator */
		tmp_pos = list->iter_pos;
		list_iterator_stop(list);
	}

	list_iterator_start(list);
	while (list_iterator_hasnext(list)) {
		sc_cardctl_coolkey_attribute_t attribute;
		current = list_iterator_next(list);
		attribute.object = current;

		for (i=0; i < count; i++) {
			attribute.attribute_type = template[i].attribute_type;
			r = coolkey_find_attribute(card, &attribute);
			if (r < 0) {
				break;
			}
			if (template[i].attribute_data_type != attribute.attribute_data_type) {
				break;
			}
			if (template[i].attribute_length != attribute.attribute_length) {
				break;
			}
			if (memcmp(attribute.attribute_value, template[i].attribute_value,
							attribute.attribute_length) != 0) {
				break;
			}
		}
		/* just return the first one */
		if (i == count) {
			rv = current;
			break;
		}
	}

	list_iterator_stop(list);
	if (tmp_pos != (unsigned int)-1) {
		/* workaround missing functionality of second iterator */
		list_iterator_start(list);
		while (list_iterator_hasnext(list) && list->iter_pos < tmp_pos)
			(void) list_iterator_next(list);
	}
	return rv;
}

static int
coolkey_find_object(sc_card_t *card, sc_cardctl_coolkey_find_object_t *fobj)
{
	sc_cardctl_coolkey_object_t *obj = NULL;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	int r;

	switch (fobj->type) {
	case SC_CARDCTL_COOLKEY_FIND_BY_ID:
		obj = coolkey_find_object_by_id(&priv->objects_list, fobj->find_id);
		break;
	case SC_CARDCTL_COOLKEY_FIND_BY_TEMPLATE:
		obj = coolkey_find_object_by_template(card, fobj->coolkey_template, fobj->template_count);
		break;
	default:
		break;
	}
	if (obj == NULL) {
		return SC_ERROR_DATA_OBJECT_NOT_FOUND;
	}
	if (obj->data == NULL) {
		r = coolkey_fill_object(card, obj);
		if (r < 0) {
			return r;
		}
	}
	fobj->obj = obj;
	return SC_SUCCESS;
}

static int coolkey_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "cmd=%ld ptr=%p", cmd, ptr);

	if (priv == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	switch(cmd) {
		case SC_CARDCTL_GET_SERIALNR:
			return coolkey_get_serial_nr_from_CUID(card, (sc_serial_number_t *) ptr);
		case SC_CARDCTL_COOLKEY_GET_TOKEN_INFO:
			return coolkey_get_token_info(card, (sc_pkcs15_tokeninfo_t *) ptr);
		case SC_CARDCTL_COOLKEY_FIND_OBJECT:
			return coolkey_find_object(card, (sc_cardctl_coolkey_find_object_t *)ptr);
		case SC_CARDCTL_COOLKEY_INIT_GET_OBJECTS:
			return coolkey_get_init_and_get_count(&priv->objects_list, (int *)ptr);
		case SC_CARDCTL_COOLKEY_GET_NEXT_OBJECT:
			return coolkey_fetch_object(&priv->objects_list, (sc_cardctl_coolkey_object_t *)ptr);
		case SC_CARDCTL_COOLKEY_FINAL_GET_OBJECTS:
			return coolkey_final_iterator(&priv->objects_list);
		case SC_CARDCTL_COOLKEY_GET_ATTRIBUTE:
			return coolkey_find_attribute(card,(sc_cardctl_coolkey_attribute_t *)ptr);
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static int coolkey_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	LOG_FUNC_CALLED(card->ctx);

	if (len > COOLKEY_MAX_CHUNK_SIZE)
		len = COOLKEY_MAX_CHUNK_SIZE;

	LOG_TEST_RET(card->ctx,
			coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_GET_RANDOM, 0, 0,
				NULL, 0, &rnd, &len,  NULL, 0),
			"Could not get challenge");

	LOG_FUNC_RETURN(card->ctx, (int) len);
}

static int coolkey_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	int r = SC_SUCCESS;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, 
		 "flags=%08lx op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 env->flags, env->operation, env->algorithm,
		 env->algorithm_flags, env->algorithm_ref, env->key_ref[0],
		 env->key_ref_len);

	if ((env->algorithm != SC_ALGORITHM_RSA) && (env->algorithm != SC_ALGORITHM_EC)) {
		 r = SC_ERROR_NO_CARD_SUPPORT;
	}
	priv->algorithm = env->algorithm;
	priv->operation = env->operation;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static int coolkey_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

#define MAX_COMPUTE_BUF 200
typedef struct coolkey_compute_crypt_init_params {
	u8 mode;
	u8 direction;
	u8 location;
	u8 buf_len[2];
} coolkey_compute_crypt_init_params_t;

typedef struct coolkey_compute_crypt_params {
    coolkey_compute_crypt_init_params_t init;
	u8 buf[MAX_COMPUTE_BUF];
} coolkey_compute_crypt_params_t;

typedef struct coolkey_compute_ecc_params {
	u8 location;
	u8 buf_len[2];
	u8 buf[MAX_COMPUTE_BUF];
} coolkey_compute_ecc_params_t;

static int coolkey_rsa_op(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t max_out_len)
{
	int r;
	const u8 *crypt_in;
	u8 **crypt_out_p;
	size_t crypt_in_len, *crypt_out_len_p;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	coolkey_compute_crypt_params_t params;
	u8 key_number;
	size_t params_len;
	size_t buf_len;
	u8 buf[MAX_COMPUTE_BUF+2];
	u8 *buf_out;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, 
		 "datalen=%"SC_FORMAT_LEN_SIZE_T"u outlen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 datalen, max_out_len);

	crypt_in = data;
	crypt_in_len = datalen;

	buf_out = &buf[0];
	crypt_out_p = &buf_out;
	buf_len = sizeof(buf);
	crypt_out_len_p = &buf_len;
	key_number = priv->key_id;
	params.init.mode = COOLKEY_CRYPT_MODE_RSA_NO_PAD;
	params.init.location = COOLKEY_CRYPT_LOCATION_APDU;
	params.init.direction = COOLKEY_CRYPT_DIRECTION_ENCRYPT; /* for no pad, direction is irrelevant */

	if (priv->key_id > 0xff) {
		r = SC_ERROR_NO_DEFAULT_KEY;
		goto done;
	}

	params_len = sizeof(params.init) + crypt_in_len;

	/* send the data to the card if necessary */
	if (crypt_in_len > MAX_COMPUTE_BUF) {
		u8 len_buf[2];
		params.init.location = COOLKEY_CRYPT_LOCATION_DL_OBJECT;
		params_len = sizeof(params.init);
		crypt_in = NULL;
		crypt_in_len = 0;
		*crypt_out_p = NULL;
		*crypt_out_len_p = 0;

		ushort2bebytes(len_buf, datalen);

		r = coolkey_write_object(card, COOLKEY_DL_OBJECT_ID, 0, len_buf, sizeof(len_buf),
					priv->nonce, sizeof(priv->nonce));
		if (r < 0) {
			goto done;
		}

		r = coolkey_write_object(card, COOLKEY_DL_OBJECT_ID, 2, data, datalen, priv->nonce,
						sizeof(priv->nonce));
		if (r < 0) {
			goto done;
		}

	}
	ushort2bebytes(params.init.buf_len, crypt_in_len);
	if (crypt_in_len) {
		memcpy(params.buf, crypt_in, crypt_in_len);
	}


	r = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_COMPUTE_CRYPT,
			key_number, COOLKEY_CRYPT_ONE_STEP, (u8 *)&params, params_len,
			crypt_out_p, crypt_out_len_p, priv->nonce, sizeof(priv->nonce));

	if (r < 0) {
		goto done;
	}
	if (datalen > MAX_COMPUTE_BUF) {
		u8 len_buf[2];
		size_t out_length;

		r = coolkey_read_object(card, COOLKEY_DL_OBJECT_ID, 0, len_buf, sizeof(len_buf),
					priv->nonce, sizeof(priv->nonce));
		if (r < 0) {
			goto done;
		}

		out_length = bebytes2ushort(len_buf);
		out_length = MIN(out_length,max_out_len);

		r = coolkey_read_object(card, COOLKEY_DL_OBJECT_ID, sizeof(len_buf), out, out_length,
					priv->nonce, sizeof(priv->nonce));

	} else {
		size_t out_length = bebytes2ushort(buf);
		out_length = MIN(out_length, max_out_len);
		memcpy(out, buf+2, out_length);
		r = out_length;
	}

done:
	return r;
}

static int coolkey_ecc_op(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	int r;
	const u8 *crypt_in;
	u8  **crypt_out_p;
	u8  ins = 0;
	size_t crypt_in_len, *crypt_out_len_p;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	coolkey_compute_ecc_params_t params;
	size_t params_len;
	u8 key_number;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, 
		 "datalen=%"SC_FORMAT_LEN_SIZE_T"u outlen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 datalen, outlen);

	crypt_in = data;
	crypt_in_len = datalen;

	crypt_out_p = &out;
	crypt_out_len_p = &outlen;
	key_number = priv->key_id;
	params.location = COOLKEY_CRYPT_LOCATION_APDU;

	if (priv->key_id > 0xff) {
		r = SC_ERROR_NO_DEFAULT_KEY;
		goto done;
	}

	switch (priv->operation) {
	case SC_SEC_OPERATION_DERIVE:
		ins = COOLKEY_INS_COMPUTE_ECC_KEY_AGREEMENT;
		break;
	case SC_SEC_OPERATION_SIGN:
		ins = COOLKEY_INS_COMPUTE_ECC_SIGNATURE;
		break;
	default:
		r = SC_ERROR_NOT_SUPPORTED;
		goto done;
	}

	params_len = (sizeof(params) - sizeof(params.buf))  + crypt_in_len;

	ushort2bebytes(params.buf_len, crypt_in_len);
	if (crypt_in_len) {
		memcpy(params.buf, crypt_in, crypt_in_len);
	}


	r = coolkey_apdu_io(card, COOLKEY_CLASS, ins,
			key_number, COOLKEY_CRYPT_ONE_STEP, (u8 *)&params, params_len,
			crypt_out_p, crypt_out_len_p, priv->nonce, sizeof(priv->nonce));

done:
	return r;
}


static int coolkey_compute_crypt(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (priv->algorithm) {
	case SC_ALGORITHM_RSA:
		r = coolkey_rsa_op(card, data, datalen, out, outlen);
		break;
	case SC_ALGORITHM_EC:
		r = coolkey_ecc_op(card, data, datalen, out, outlen);
		break;
	default:
		r = SC_ERROR_NO_CARD_SUPPORT;
		break;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static u8 coolkey_class(unsigned long object_id) {
	return (object_id >> 24) & 0xff;
}

static unsigned short coolkey_get_key_id(unsigned long object_id) {
	char char_index = (object_id >> 16) & 0xff;
	if (char_index >= '0' && char_index <= '9') {
		return (u8)(char_index - '0');
	}
	if (char_index >= 'A' && char_index <= 'Z') {
		return (u8)(char_index - 'A' + 10);
	}
	if (char_index >= 'a' && char_index <= 'z') {
		return (u8)(char_index - 'a' + 26 + 10);
	}
	return COOLKEY_INVALID_KEY;
}

/*
 * COOLKEY cards don't select objects in the applet, objects are selected by a parameter
 * to the APDU. We create paths for the object in which the path value is the object_id
 * and the path type is SC_PATH_SELECT_FILE_ID (so we could cache at the PKCS #15 level if
 * we wanted to.
 *
 * This select simply records what object was selected so that read knows how to access it.
 */
static int coolkey_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	int r;
	struct sc_file *file = NULL;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	unsigned long object_id;

	assert(card != NULL && in_path != NULL);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (in_path->len != 4) {
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	r = coolkey_select_applet(card);
	if (r != SC_SUCCESS) {
		return r;
	}
	object_id = bebytes2ulong(in_path->value);
	priv->obj = coolkey_find_object_by_id(&priv->objects_list, object_id);
	if (priv->obj == NULL) {
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	priv->key_id = COOLKEY_INVALID_KEY;
	if (coolkey_class(object_id) == COOLKEY_KEY_CLASS) {
		priv->key_id = coolkey_get_key_id(object_id);
	}
	if (file_out) {
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		/* this could be like the FCI */
		file->type =  SC_PATH_TYPE_FILE_ID;
		file->shareable = 0;
		file->ef_structure = 0;
		file->size = priv->obj->length;
		*file_out = file;
	}

	return SC_SUCCESS;
}

static int coolkey_finish(sc_card_t *card)
{
	coolkey_private_data_t * priv = COOLKEY_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		coolkey_free_private_data(priv);
	}
	return SC_SUCCESS;
}

static int
coolkey_add_object(coolkey_private_data_t *priv, unsigned long object_id, const u8 *object_data, size_t object_length, int add_v1_record)
{
	sc_cardctl_coolkey_object_t new_object;
	int r;

	memset(&new_object, 0, sizeof(new_object));
	new_object.path = coolkey_template_path;
	new_object.path.len = 4;
	ulong2bebytes(new_object.path.value, object_id);
	new_object.id = object_id;
	new_object.length = object_length;

	/* The object ID needs to be unique */
	if (coolkey_find_object_by_id(&priv->objects_list, object_id) != NULL) {
		return SC_ERROR_INTERNAL;
	}

	if (object_data) {
		new_object.data = malloc(object_length + add_v1_record);
		if (new_object.data == NULL) {
			return SC_ERROR_OUT_OF_MEMORY;
		}
		if (add_v1_record) {
			new_object.data[0] = COOLKEY_V1_OBJECT;
			new_object.length++;
		}
		memcpy(&new_object.data[add_v1_record], object_data, object_length);
	}

	r = coolkey_add_object_to_list(&priv->objects_list, &new_object);
	if (r != SC_SUCCESS) {
		/* if we didn't successfully put the object on the list,
		 * the data space didn't get adopted. free it before we return */
		free(new_object.data);
		new_object.data = NULL;
	}
	return r;
}


static int
coolkey_process_combined_object(sc_card_t *card, coolkey_private_data_t *priv, u8 *object, size_t object_length)
{
	coolkey_combined_header_t *header = (coolkey_combined_header_t *)object;
	unsigned short compressed_offset;
	unsigned short compressed_length;
	unsigned short compressed_type;
	unsigned short object_offset;
	unsigned short object_count;
	coolkey_decompressed_header_t *decompressed_header;
	u8 *decompressed_object = NULL;
	size_t decompressed_object_len = 0;
	int free_decompressed = 0;
	int i, r;

	if (object_length < sizeof(coolkey_combined_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	compressed_offset = bebytes2ushort(header->compression_offset);
	compressed_length = bebytes2ushort(header->compression_length);
	compressed_type   = bebytes2ushort(header->compression_type);

	if ((((size_t)compressed_offset) + (size_t)compressed_length) >  object_length) {
		return SC_ERROR_CORRUPTED_DATA;
	}

	/* store the CUID */
	memcpy(&priv->cuid, &header->cuid, sizeof(priv->cuid));

	if (compressed_type == COOLKEY_COMPRESSION_ZLIB) {
#ifdef ENABLE_ZLIB
		r = sc_decompress_alloc(&decompressed_object, &decompressed_object_len, &object[compressed_offset], compressed_length, COMPRESSION_AUTO);
		if (r)
			goto done;
		free_decompressed = 1;
#else
		sc_log(card->ctx, "Coolkey compression not supported, no zlib");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
#endif
	}  else {
		decompressed_object =&object[compressed_offset];
		decompressed_object_len = (size_t) compressed_length;
	}

	decompressed_header = (coolkey_decompressed_header_t *)decompressed_object;

	if (decompressed_object_len < sizeof(coolkey_decompressed_header_t)) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	object_offset = bebytes2ushort(decompressed_header->object_offset);
	object_count = bebytes2ushort(decompressed_header->object_count);


	/*
	 * using 2 different tests here so we can log different errors if logging is
	 * turned on.
	 */
	/* make sure token_name doesn't overrun the buffer */
	if (decompressed_header->token_name_length +
		offsetof(coolkey_decompressed_header_t,token_name) > decompressed_object_len) {
		r = SC_ERROR_CORRUPTED_DATA;
		goto done;
	}
	/* make sure it doesn't overlap the object space */
	if (decompressed_header->token_name_length +
		offsetof(coolkey_decompressed_header_t,token_name) > object_offset) {
		r = SC_ERROR_CORRUPTED_DATA;
		goto done;
	}

	/* store the token name in the priv structure so the emulator can set it */
	priv->token_name = malloc(decompressed_header->token_name_length+1);
	if (priv->token_name == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(priv->token_name, &decompressed_header->token_name[0],
							decompressed_header->token_name_length);
	priv->token_name[decompressed_header->token_name_length] = 0;
	priv->token_name_length = decompressed_header->token_name_length;


	for (i=0; i < object_count; i++) {
		u8 *current_object = NULL;
		coolkey_combined_object_header_t *object_header = NULL;
		unsigned long object_id;
		int current_object_len;

		/* Can we read the object header at all? */
		if ((object_offset + sizeof(coolkey_combined_object_header_t)) > decompressed_object_len) {
			r = SC_ERROR_CORRUPTED_DATA;
			goto done;
		}

		current_object = &decompressed_object[object_offset];
		object_header = (coolkey_combined_object_header_t *)current_object;

		/* Parse object ID */
		object_id = bebytes2ulong(object_header->object_id);

		/* figure out how big it is */
		r = coolkey_v1_get_object_length(current_object, decompressed_object_len-object_offset);
		if (r < 0) {
			goto done;
		}
		if ((size_t)r + object_offset > decompressed_object_len) {
			r = SC_ERROR_CORRUPTED_DATA;
			goto done;
		}
		current_object_len = r;
		object_offset += current_object_len;

		/* record this object */
		sc_log(card->ctx, "Add new object id=%ld", object_id);
		r = coolkey_add_object(priv, object_id, current_object, current_object_len, 1);
		if (r) {
			goto done;
		}

	}
	r = SC_SUCCESS;

done:
	if (free_decompressed) {
		free(decompressed_object);
	}
	return r;
}

static int
coolkey_list_object(sc_card_t *card, u8 seq, coolkey_object_info_t *object_info)
{
	u8 *rbuf = (u8 *) object_info;
	size_t rbuflen = sizeof(*object_info);

	return coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_LIST_OBJECTS, seq, 0,
			NULL, 0, &rbuf, &rbuflen, NULL, 0);

}

/*
 * Initialize the Coolkey data structures.
 */
static int coolkey_initialize(sc_card_t *card)
{
	int r;
	coolkey_private_data_t *priv = NULL;
	coolkey_life_cycle_t life_cycle;
	coolkey_object_info_t object_info;
	int combined_processed = 0;

	/* already found? */
	if (card->drv_data) {
		return SC_SUCCESS;
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"Coolkey Applet found");

	priv = coolkey_new_private_data();
	if (priv == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto cleanup;
	}
	r = coolkey_get_life_cycle(card, &life_cycle);
	if (r < 0) {
		goto cleanup;
	}

	/* Select a coolkey read the coolkey objects out */
	r = coolkey_select_applet(card);
	if (r < 0) {
		goto cleanup;
	}

	priv->protocol_version_major = life_cycle.protocol_version_major;
	priv->protocol_version_minor = life_cycle.protocol_version_minor;
	priv->pin_count = life_cycle.pin_count;
	priv->life_cycle = life_cycle.life_cycle;

	/* walk down the list of objects and read them off the token */
	r = coolkey_list_object(card, COOLKEY_LIST_RESET, &object_info);
	while (r >= 0) {
		unsigned long object_id;
		unsigned short object_len;

		/* The card did not return what we expected: Lets try other objects */
		if ((size_t)r < (sizeof(object_info)))
			break;

		/* TODO also look at the ACL... */

		object_id = bebytes2ulong(object_info.object_id);
		object_len = bebytes2ulong(object_info.object_length);


		/* the combined object is a single object that can store the other objects.
		 * most coolkeys provisioned by TPS has a single combined object that is
		 * compressed greatly increasing the effectiveness of compress (since lots
		 * of certs on the token share the same Subject and Issuer DN's). We now
		 * process it separately so that we can have both combined objects managed
		 * by TPS and user managed certs on the same token */
		if (object_id == COOLKEY_COMBINED_OBJECT_ID) {
			u8 *object = malloc(object_len);
			if (object == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				break;
			}
			r = coolkey_read_object(card, COOLKEY_COMBINED_OBJECT_ID, 0, object, object_len,
				priv->nonce, sizeof(priv->nonce));
			if (r < 0) {
				free(object);
				break;
			}
			r = coolkey_process_combined_object(card, priv, object, r);
			free(object);
			if (r != SC_SUCCESS) {
				break;
			}
			combined_processed = 1;
		} else {
			sc_log(card->ctx, "Add new object id=%ld, len=%u", object_id, object_len);
			r = coolkey_add_object(priv, object_id, NULL, object_len, 0);
			if (r != SC_SUCCESS)
				sc_log(card->ctx, "coolkey_add_object() returned %d", r);
		}

		/* Read next object: error is handled on the cycle condition and below after cycle */
		r = coolkey_list_object(card, COOLKEY_LIST_NEXT, &object_info);
	}
	if (r != SC_ERROR_FILE_END_REACHED) {
		/* This means the card does not cooperate at all: bail out */
		if (r >= 0) {
			r = SC_ERROR_INVALID_CARD;
		}
		goto cleanup;
	}
	/* if we didn't pull the cuid from the combined object, then grab it now */
	if (!combined_processed) {
		global_platform_cplc_data_t cplc_data;
		/* select the card manager, because a card with applet only will have
		   already selected the coolkey applet */

		r = gp_select_card_manager(card);
		if (r < 0) {
			goto cleanup;
		}

		r = gp_get_cplc_data(card, &cplc_data);
		if (r < 0) {
			goto cleanup;
		}
		coolkey_make_cuid_from_cplc(&priv->cuid, &cplc_data);
		priv->token_name = (u8 *)strdup("COOLKEY");
		if (priv->token_name == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto cleanup;
		}
		priv->token_name_length = sizeof("COOLKEY")-1;
	}
	card->drv_data = priv;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

cleanup:
	if (priv) {
		coolkey_free_private_data(priv);
	}
	LOG_FUNC_RETURN(card->ctx, r);
}


/* NOTE: returns a bool, 1 card matches, 0 it does not */
static int coolkey_match_card(sc_card_t *card)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* Since we send an APDU, the card's logout function may be called...
	 * however it may be in dirty memory */
	card->ops->logout = NULL;

	r = coolkey_select_applet(card);
	if (r == SC_SUCCESS) {
		sc_apdu_t apdu;

		/* The GET STATUS INS with P1 = 1 returns invalid instruction (0x6D00)
		 * on Coolkey applet (reserved for GetMemory function),
		 * while incorrect P1 (0x9C10) on Muscle applets
		 */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, COOLKEY_INS_GET_STATUS, 0x01, 0x00);
		apdu.cla = COOLKEY_CLASS;
		apdu.le = 0x00;
		apdu.resplen = 0;
		apdu.resp = NULL;
		r = sc_transmit_apdu(card, &apdu);
		if (r == SC_SUCCESS && apdu.sw1 == 0x6d && apdu.sw2 == 0x00) {
			return 1;
		}
		return 0;
	}
	return 0;
}


static int coolkey_init(sc_card_t *card)
{
	int r;
	unsigned long flags;
	unsigned long ext_flags;
	coolkey_private_data_t * priv;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = coolkey_initialize(card);
	if (r < 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}

	card->type = SC_CARD_TYPE_COOLKEY_GENERIC;

	/* set Token Major/minor version */
	flags = SC_ALGORITHM_RSA_RAW;

	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* mandatory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
	ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

	_sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
	_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);
	_sc_card_add_ec_alg(card, 521, flags, ext_flags, NULL);


	priv = COOLKEY_DATA(card);
	if (priv->pin_count != 0) {
		card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
coolkey_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	size_t rbuflen;
	u8 *rbuf;

	/* COOLKEY uses a separate pin from the card pin, managed by the applet.
	 * if we successfully log into coolkey, we will get a nonce, which we append
	 * to our APDUs to authenticate the apdu to the card. This allows coolkey to
	 * maintain separate per application login states without the application
	 * having to cache the pin */
	switch (data->cmd) {
	case SC_PIN_CMD_GET_INFO:
		if (priv->nonce_valid) {
			data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
		} else {
			data->pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
			/* coolkey retries is 100. It's unlikely the pin is block.
			 * instead, coolkey slows down the login command exponentially
			 */
			data->pin1.tries_left = 0xf;
		}
		if (tries_left) {
			*tries_left = data->pin1.tries_left;
		}
		r = SC_SUCCESS;
		break;

	case SC_PIN_CMD_UNBLOCK:
	case SC_PIN_CMD_CHANGE:
		/* these 2 commands are currently reserved for TPS */
	default:
		r = SC_ERROR_NOT_SUPPORTED;
		break;
	case SC_PIN_CMD_VERIFY:
		/* coolkey applet supports multiple pins, but TPS currently only uses one.
		 * just support the one pin for now (we need an array of nonces to handle
		 * multiple pins) */
		/* coolkey only supports unpadded ascii pins, so no need to format the pin */
		rbuflen = sizeof(priv->nonce);
		rbuf = &priv->nonce[0];
		r = coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_VERIFY_PIN,
			data->pin_reference, 0, data->pin1.data, data->pin1.len,
			&rbuf, &rbuflen, NULL, 0);
		if (r < 0) {
			break;
		}
		priv->nonce_valid = 1;
		r = SC_SUCCESS;
	}
	return r;
}


static int
coolkey_logout(sc_card_t *card)
{
	/* when we add multi pin support here, how do we know which pin to logout? */
	coolkey_private_data_t * priv = COOLKEY_DATA(card);
	u8 pin_ref = 0;

	(void) coolkey_apdu_io(card, COOLKEY_CLASS, COOLKEY_INS_LOGOUT, pin_ref, 0, NULL, 0, NULL, NULL,
		priv->nonce, sizeof(priv->nonce));
	/* even if logout failed on the card, flush the nonce and clear the nonce_valid and we are effectively
	 * logged out... needing to login again to get a nonce back */
	memset(priv->nonce, 0, sizeof(priv->nonce));
	priv->nonce_valid = 0;
	return SC_SUCCESS;
}


static int coolkey_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0) {
		r = coolkey_select_applet(card);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_operations coolkey_ops;

static struct sc_card_driver coolkey_drv = {
	"COOLKEY",
	"coolkey",
	&coolkey_ops,
	NULL, 0, NULL
};

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	coolkey_ops = *iso_drv->ops;
	coolkey_ops.match_card = coolkey_match_card;
	coolkey_ops.init = coolkey_init;
	coolkey_ops.finish = coolkey_finish;

	coolkey_ops.select_file =  coolkey_select_file; /* need to record object type */
	coolkey_ops.get_challenge = coolkey_get_challenge;
	coolkey_ops.read_binary = coolkey_read_binary;
	coolkey_ops.write_binary = coolkey_write_binary;
	coolkey_ops.set_security_env = coolkey_set_security_env;
	coolkey_ops.restore_security_env = coolkey_restore_security_env;
	coolkey_ops.compute_signature = coolkey_compute_crypt;
	coolkey_ops.decipher =  coolkey_compute_crypt;
	coolkey_ops.card_ctl = coolkey_card_ctl;
	coolkey_ops.check_sw = coolkey_check_sw;
	coolkey_ops.pin_cmd = coolkey_pin_cmd;
	coolkey_ops.logout = coolkey_logout;
	coolkey_ops.card_reader_lock_obtained = coolkey_card_reader_lock_obtained;

	return &coolkey_drv;
}


struct sc_card_driver * sc_get_coolkey_driver(void)
{
	return sc_get_driver();
}

