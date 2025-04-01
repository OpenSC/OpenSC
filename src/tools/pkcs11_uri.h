#ifndef PKCS11_URI_H
#define PKCS11_URI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PKCS11_URI_SCHEME "pkcs11:"

typedef enum {
	PKCS11_ID = 0,
	PKCS11_LIB_DESCRIPTION,
	PKCS11_LIB_MANUFACTURER,
	PKCS11_LIB_VERSION,
	PKCS11_MANUFACTURER,
	PKCS11_MODEL,
	PKCS11_OBJECT,
	PKCS11_SERIAL,
	PKCS11_SLOT_DESCRIPTION,
	PKCS11_SLOT_ID,
	PKCS11_SLOT_MANUFACTURER,
	PKCS11_TOKEN,
	PKCS11_TYPE
} pkcs11_uri_attr_code;

typedef enum {
	PKCS11_PIN_SOURCE = 0,
	PKCS11_PIN_VALUE,
	PKCS11_MODULE_NAME,
	PKCS11_MODULE_PATH
} pkcs11_uri_query_code;

struct pkcs11_uri {
	/* taken from https://www.rfc-editor.org/rfc/rfc7512.html mapping of the PKCS #11 URI path component attributes */
	char *id;
	int id_len;
	char *library_description;
	char *library_manufacturer;
	char *library_version;
	char *token_manufacturer;
	char *token_model;
	char *object;
	char *serial;
	char *slot_description;
	char *slot_id;
	char *slot_manufacturer;
	char *token_label;
	char *type;
	/* query */
	char *pin_source;
	char *pin;
	char *module_name;
	char *module_path;
};

struct pkcs11_uri_attr {
	char *name;
	int id;
};

struct pkcs11_uri *pkcs11_uri_new();
int parse_pkcs11_uri(const char *input_string, struct pkcs11_uri *result);
void pkcs11_uri_free(struct pkcs11_uri *uri);

#endif // PKCS11_URI_H
