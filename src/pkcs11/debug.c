/*
 * Debugging stuff for pkcs11
 *
 * Copyright (C) 2003 Olaf Kirch <okir@suse.de>
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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "sc-pkcs11.h"

#define DUMP_TEMPLATE_MAX	32

struct fmap {
	CK_ULONG	value;
	const char *	name;
	const char *	(*print)(int level, struct fmap *, void *, size_t);
	struct fmap *	map;
};

#define _(x)		{ (x), #x, NULL, NULL }
#define ul(x)		{ (x), #x, sc_pkcs11_print_ulong, NULL }
#define ulm(x)		{ (x), #x, sc_pkcs11_print_ulong, map_##x }
#define b(x)		{ (x), #x, sc_pkcs11_print_bool, NULL }
#define s(x)		{ (x), #x, sc_pkcs11_print_string, NULL }

static void		sc_pkcs11_print_attr(int level, const char *,
				unsigned int, const char *, const char *,
				CK_ATTRIBUTE_PTR);
static const char *	sc_pkcs11_print_value(int level, struct fmap *,
				void *, size_t);
static struct fmap *	sc_pkcs11_map_ulong(int level, struct fmap *,
				CK_ULONG);
static const char *	sc_pkcs11_print_ulong(int level, struct fmap *,
				void *, size_t);
static const char *	sc_pkcs11_print_bool(int level, struct fmap *,
				void *, size_t);
static const char *	sc_pkcs11_print_string(int level, struct fmap *,
				void *, size_t);

static struct fmap	map_CKA_CLASS[] = {
	_(CKO_DATA),
	_(CKO_CERTIFICATE),
	_(CKO_PUBLIC_KEY),
	_(CKO_PRIVATE_KEY),
	_(CKO_SECRET_KEY),
	_(CKO_HW_FEATURE),
	_(CKO_DOMAIN_PARAMETERS),

	{ 0, NULL, NULL, NULL }
};

static struct fmap	map_CKA_CERTIFICATE_TYPE[] = {
	_(CKC_X_509),
	_(CKC_X_509_ATTR_CERT),

	{ 0, NULL, NULL, NULL }
};

static struct fmap	map_CKA_KEY_TYPE[] = {
	_(CKK_RSA),
	_(CKK_DSA),
	_(CKK_DH),
	_(CKK_ECDSA),
	_(CKK_EC),
	_(CKK_RC2),
	_(CKK_RC4),
	_(CKK_RC5),
	_(CKK_DES),
	_(CKK_DES3),
	_(CKK_CAST),
	_(CKK_CAST3),
	_(CKK_CAST128),
	_(CKK_IDEA),
	_(CKK_AES),

	{ 0, NULL, NULL, NULL }
};

static struct fmap	p11_attr_names[] = {
	ulm(CKA_CLASS),
	b(CKA_TOKEN),
	b(CKA_PRIVATE),
	s(CKA_LABEL),
	_(CKA_APPLICATION),
	_(CKA_VALUE),
	_(CKA_OBJECT_ID),
	ulm(CKA_CERTIFICATE_TYPE),
	_(CKA_ISSUER),
	_(CKA_SERIAL_NUMBER),
	_(CKA_AC_ISSUER),
	_(CKA_OWNER),
	_(CKA_ATTR_TYPES),
	b(CKA_TRUSTED),
	ulm(CKA_KEY_TYPE),
	_(CKA_SUBJECT),
	_(CKA_ID),
	b(CKA_SENSITIVE),
	b(CKA_ENCRYPT),
	b(CKA_DECRYPT),
	b(CKA_WRAP),
	b(CKA_UNWRAP),
	b(CKA_SIGN),
	b(CKA_SIGN_RECOVER),
	b(CKA_VERIFY),
	b(CKA_VERIFY_RECOVER),
	b(CKA_DERIVE),
	_(CKA_START_DATE),
	_(CKA_END_DATE),
	_(CKA_MODULUS),
	ul(CKA_MODULUS_BITS),
	_(CKA_PUBLIC_EXPONENT),
	_(CKA_PRIVATE_EXPONENT),
	_(CKA_PRIME_1),
	_(CKA_PRIME_2),
	_(CKA_EXPONENT_1),
	_(CKA_EXPONENT_2),
	_(CKA_COEFFICIENT),
	_(CKA_PRIME),
	_(CKA_SUBPRIME),
	_(CKA_BASE),
	_(CKA_PRIME_BITS),
	_(CKA_SUB_PRIME_BITS),
	_(CKA_VALUE_BITS),
	_(CKA_VALUE_LEN),
	b(CKA_EXTRACTABLE),
	b(CKA_LOCAL),
	b(CKA_NEVER_EXTRACTABLE),
	b(CKA_ALWAYS_SENSITIVE),
	_(CKA_KEY_GEN_MECHANISM),
	b(CKA_MODIFIABLE),
	_(CKA_ECDSA_PARAMS),
	_(CKA_EC_PARAMS),
	_(CKA_EC_POINT),
	_(CKA_SECONDARY_AUTH),
	ul(CKA_AUTH_PIN_FLAGS),
	_(CKA_HW_FEATURE_TYPE),
	_(CKA_RESET_ON_INIT),
	_(CKA_HAS_RESET),
	_(CKA_VENDOR_DEFINED),
	b(CKA_ALWAYS_AUTHENTICATE),
	_(CKA_GOSTR3410_PARAMS),

	{ 0, NULL, NULL, NULL }
};

void sc_pkcs11_print_attrs(int level, const char *file, unsigned int line,
			const char *function,
			const char *info,
			CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (ulCount == 0) {
		sc_do_log(context, level,
			file, line, function,
			"%s: empty template\n",
			info);
		return;
	}

	while (ulCount--)
		sc_pkcs11_print_attr(level, file, line, function,
				info, pTemplate++);

}

static void sc_pkcs11_print_attr(int level, const char *file, unsigned int line,
			const char *function,
			const char *info, CK_ATTRIBUTE_PTR attr)
{
	struct fmap	*fm;
	const char *	value;

	fm = sc_pkcs11_map_ulong(level, p11_attr_names, attr->type);

	if (attr->pValue == NULL) {
		value = "<size inquiry>";
	} else {
		value = sc_pkcs11_print_value(level, fm,
			attr->pValue, attr->ulValueLen);
	}

	if (fm == NULL) {
		sc_do_log(context, level,
			  file, line, function,
			  "%s: Attribute 0x%lx = %s\n",
			  info, attr->type, value);
	} else {
		sc_do_log(context, level,
			  file, line, function,
			  "%s: %s = %s\n",
			  info, fm->name, value);
	}
}

static const char *sc_pkcs11_print_value(int level, struct fmap *fm,
			void *ptr, size_t count)
{
	static char buffer[4 * DUMP_TEMPLATE_MAX + 1] = "";

	if (count == (CK_ULONG)-1)
		return "<error>";

	if (!fm || !fm->print) {
		unsigned char *value = (unsigned char*) ptr;
		char	*p;

		if (count > DUMP_TEMPLATE_MAX)
			count = DUMP_TEMPLATE_MAX;

		for (p = buffer; count--; value++)
			p += sprintf(p, "%02X", *value);
		return buffer;
	}

	return fm->print(level, fm, ptr, count);
}

static const char *sc_pkcs11_print_ulong(int level, struct fmap *fm,
		void *ptr, size_t count)
{
	static char	buffer[64];
	CK_ULONG	value;

	if (count == sizeof(CK_ULONG)) {
		memcpy(&value, ptr, count);
		if ((fm = sc_pkcs11_map_ulong(level, fm->map, value)) != NULL)
			return fm->name;
		sprintf(buffer, "0x%lx", (unsigned long) value);
		return buffer;
	}

	return sc_pkcs11_print_value(level, NULL, ptr, count);
}

static const char *sc_pkcs11_print_bool(int level, struct fmap *fm,
		void *ptr, size_t count)
{
	CK_BBOOL	value;

	if (count == sizeof(CK_BBOOL)) {
		memcpy(&value, ptr, count);
		if (value)
			return "TRUE";
		return "FALSE";
	}

	return sc_pkcs11_print_value(level, NULL, ptr, count);
}

static const char *sc_pkcs11_print_string(int level, struct fmap *fm,
		void *ptr, size_t count)
{
	static char	buffer[128];

	if (count >= sizeof(buffer))
		count = sizeof(buffer)-1;
	memcpy(buffer, ptr, count);
	buffer[count] = 0;
	return buffer;
}

static struct fmap *sc_pkcs11_map_ulong(int level, struct fmap *fm, CK_ULONG value)
{
	for (; fm && fm->name; fm++) {
		if (fm->value == value)
			return fm;
	}
	return NULL;
}

