/*
 * pkcs11-uri.c: PKCS#11 URI Parser
 *
 * Copyright (C) 2024 Veronika Hanulikova <vhanulik@redhat.com>
 * Original parser implementation: https://src.fedoraproject.org/rpms/openssh/blob/rawhide/f/openssh-8.0p1-pkcs11-uri.patch
 *
 * This file is part of OpenSC.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_uri.h"

static struct pkcs11_uri_attr path_attr[] = {
		{"id", 0},
		{"library-description", 1},
		{"library-manufacturer", 2},
		{"library-version", 3},
		{"manufacturer", 4},
		{"model", 5},
		{"object", 6},
		{"serial", 7},
		{"slot-description", 8},
		{"slot-id", 9},
		{"slot-manufacturer", 10},
		{"token", 11},
		{"type", 12},
		{NULL, 0}
};

static struct pkcs11_uri_attr query_attr[] = {
		{"pin-source", 0},
		{"pin-value", 1},
		{"module-name", 2},
		{"module-path", 3},
		{NULL, 0}
};

static int
get_attr(struct pkcs11_uri_attr attr[], char *token)
{
	for (int i = 0; attr[i].name; i++) {
		if (strncasecmp(token, attr[i].name, strlen(attr[i].name)) == 0	&&
				*(token + strlen(attr[i].name)) == '=')
			return attr[i].id;
	}
	return -1;
}

static int
decode_percent_string(char *data, char **out)
{
	char tmp[3];
	char *decoded, *tmp_end;
	char *p = data;
	long value;
	size_t decoded_len = 0;

	decoded = malloc(strlen(data) + 1);
	if (decoded == NULL)
		return -1;
	while (*p != '\0') {
		switch (*p) {
		case '%':
			p++;
			if (*p == '\0')
				goto fail;
			tmp[0] = *p++;
			if (*p == '\0')
				goto fail;
			tmp[1] = *p++;
			tmp[2] = '\0';
			tmp_end = NULL;
			errno = 0;
			value = strtol(tmp, &tmp_end, 16);
			if (errno == EINVAL)
				goto fail;
			if (tmp_end != tmp + 2)
				goto fail;
			else
				decoded[decoded_len++] = (char)value;
			break;
		default:
			decoded[decoded_len++] = *p++;
			break;
		}
	}

	/* zero terminate */
	decoded[decoded_len] = '\0';
	*out = decoded;
	return decoded_len;
fail:
	free(decoded);
	return -1;
}

static int
parse_string(char *argument, char **out, int *out_len, int max_len)
{
	int rv = 0, len = 0;
	char *tmp = NULL;
	if (*out != NULL) {
		rv = 1;
		fprintf(stderr, "Attribute already set\n");
		goto end;
	}
	len = decode_percent_string(argument, &tmp);
	if (len < 0) {
		rv = 1;
		fprintf(stderr, "Invalid percent decode result\n");
		goto end;
	}
	if (max_len >= 0 && max_len < len) {
		rv = 1;
		free(tmp);
		fprintf(stderr, "Invalid length of decoded result\n");
		goto end;
	}
	*out = tmp;
	if (out_len != NULL) {
		*out_len = len;
	}
end:
	return rv;
}

struct pkcs11_uri *
pkcs11_uri_new()
{
	struct pkcs11_uri *uri = calloc(1, sizeof(struct pkcs11_uri));
	return uri;
}

int
parse_pkcs11_uri(const char *input_string, struct pkcs11_uri *result)
{
	size_t length = 0;
	char *uri;
	char *path, *query, *token;
	int rv = 0;

	if (!input_string || !result) {
		return 1;
	}

	/* Check PKCS#11 URI scheme */
	length = strlen(PKCS11_URI_SCHEME);
	if (strlen(input_string) < length || strncmp(input_string, PKCS11_URI_SCHEME, length) != 0) {
		return 1;
	}

	/* Divide path and query part*/
	if ((uri = strdup(input_string)) == NULL) {
		rv = 1;
		fprintf(stderr, "Error when allocating memory\n");
		goto end;
	}
	path = uri;
	path = strtok(path, "?");
	query = strtok(NULL, "?");
	if (path == NULL) {
		rv = 1;
		goto end;
	}
	/* Skip PKCS#11 URI scheme*/
	path = path + length;

	/* parse path */
	token = strtok(path, ";");
	while (token != NULL) {
		char *argument = NULL, **result_ptr = NULL;
		int *result_len = NULL;
		int max_len = -1;
		int id = get_attr(path_attr, token);
		if (id == -1) {
			rv = 1;
			fprintf(stderr, "Invalid PKCS#11 token\n");
			goto end;
		}
		argument = token + strlen(path_attr[id].name) + 1;

		switch (id) {
		case 0: /* CKA_ID */
			result_ptr = &result->id;
			result_len = &result->id_len;
			break;
		case 1: /* CK_INFO -> libraryDescription */
			rv = 1;
			fprintf(stderr, "PKCS#11 library description not supported\n");
			goto end;
			break;
		case 2: /* CK_INFO -> manufacturerID */
			rv = 1;
			fprintf(stderr, "PKCS#11 manufacturer ID not supported\n");
			goto end;
			break;
		case 3: /* CK_INFO -> libraryVersion*/
			rv = 1;
			fprintf(stderr, "PKCS#11 library version not supported\n");
			goto end;
			break;
		case 4: /* CK_TOKEN_INFO -> manufacturerID */
			result_ptr = &result->token_manufacturer;
			max_len = 32;
			break;
		case 5: /* CK_TOKEN_INFO -> model */
			result_ptr = &result->token_model;
			max_len = 16;
			break;
		case 6: /* CKA_LABEL */
			result_ptr = &result->object;
			break;
		case 7: /* CK_TOKEN_INFO -> serialNumber */
			result_ptr = &result->serial;
			max_len = 16;
			break;
		case 8: /* CK_SLOT_INFO -> slotDescription */
			result_ptr = &result->slot_description;
			break;
		case 9: /* CK_SLOT_ID */
			result_ptr = &result->slot_id;
			break;
		case 10: /* CK_SLOT_INFO -> manufacturerID */
			result_ptr = &result->slot_manufacturer;
			break;
		case 11: /* CK_TOKEN_INFO -> label */
			result_ptr = &result->token_label;
			max_len = 32;
			break;
		case 12: /* CKA_CLASS */
			result_ptr = &result->type;
			break;
		}
		if (parse_string(argument, result_ptr, result_len, max_len) != 0) {
			rv = 1;
			goto end;
		}
		token = strtok(NULL, ";");
	}

	/* parse query */
	if (query == NULL) {
		goto end;
	}
	token = strtok(query, ";");
	while (token != NULL) {
		char *argument = NULL, **result_ptr = NULL;
		int id = get_attr(query_attr, token);
		if (id == -1) {
			rv = 1;
			fprintf(stderr, "Invalid PKCS#11 URI query\n");
			goto end;
		}
		argument = token + strlen(query_attr[id].name) + 1;

		switch (id) {
		case 0:
			if (result->pin != NULL) {
				rv = 1;
				fprintf(stderr, "A pin and pin-source cannot be specified together in PKCS#11 URI\n");
				goto end;
			}
			result_ptr = &result->pin_source;
			break;
		case 1:
			if (result->pin_source != NULL) {
				rv = 1;
				fprintf(stderr, "A pin and pin-source cannot be specified together in PKCS#11 URI\n");
				goto end;
			}
			result_ptr = &result->pin;
			break;
		case 2:
			rv = 1;
			fprintf(stderr, "PKCS#11 module name for query not supported\n");
			goto end;
			break;
		case 3:
			result_ptr = &result->module_path;
			break;
		}
		if (parse_string(argument, result_ptr, NULL, -1) != 0) {
			rv = 1;
			goto end;
		}
		token = strtok(NULL, ";");
	}

end:
	free(uri);
	return rv;
}

void
pkcs11_uri_free(struct pkcs11_uri *uri)
{
	if (uri == NULL) {
		return;
	}

	free(uri->id);
	free(uri->library_description);
	free(uri->library_manufacturer);
	free(uri->library_version);
	free(uri->token_manufacturer);
	free(uri->token_model);
	free(uri->object);
	free(uri->serial);
	free(uri->slot_description);
	free(uri->slot_id);
	free(uri->slot_manufacturer);
	free(uri->token_label);
	free(uri->type);
	free(uri->pin_source);
	if (uri->pin) {
		memset(uri->pin, 0, strlen(uri->pin));
		free(uri->pin);
	}
	free(uri->module_name);
	free(uri->module_path);
	free(uri);
}
