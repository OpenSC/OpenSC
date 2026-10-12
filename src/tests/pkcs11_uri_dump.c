/*
 * pkcs11_uri_dump.c: Dump parts of parsed PKCS#11 URI
 *
 * Copyright (C) 2026 Red Hat, LLC
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pkcs11/pkcs11.h"
#include "tools/pkcs11_uri.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
print_hex_attr(const char *key, const char *val, size_t len)
{
	if (!val)
		return;

	printf("%s=", key);
	for (size_t i = 0; i < len; i++) {
		printf("%02X", (unsigned char)val[i]);
	}
	printf("\n");
}

static void
print_hex_str(const char *key, const char *val)
{
	if (!val)
		return;
	print_hex_attr(key, val, strlen(val));
}

static void
print_str(const char *key, const char *val)
{
	if (!val)
		return;
	printf("%s=%s\n", key, val);
}

int
main(int argc, char **argv)
{
	struct pkcs11_uri *uri = NULL;
	int rv;

	if (argc != 2) {
		fprintf(stderr, "This tool requires valid PKCS#11 uri as an argument\n");
		return 1;
	}

	uri = pkcs11_uri_new();
	if (uri == NULL) {
		return 1;
	}
	rv = parse_pkcs11_uri(argv[1], uri);
	if (rv != 0) {
		fprintf(stderr, "Failed to parse PKCS#11 URI\n");
		return 1;
	}

	print_hex_str("library-description", uri->library_description);
	print_hex_str("library-manufacturer", uri->library_manufacturer);
	print_str("library-version", uri->library_version);
	print_hex_str("token", uri->token_label);
	print_hex_str("manufacturer", uri->token_manufacturer);
	print_hex_str("model", uri->token_model);
	print_hex_str("serial", uri->serial);
	print_hex_str("slot-description", uri->slot_description);
	print_str("slot-id", uri->slot_id);
	print_hex_attr("id", uri->id, uri->id_len);
	print_hex_str("object", uri->object);
	print_str("type", uri->type);
	print_str("pin-value", uri->pin_value);
	print_str("pin-source", uri->pin_source);
	print_str("module-name", uri->module_name);
	print_str("module-path", uri->module_path);

	pkcs11_uri_free(uri);
	return 0;
}
