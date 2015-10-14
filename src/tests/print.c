/* Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 PIN code test
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "sc-test.h"

void sc_test_print_card(const sc_pkcs15_card_t *mycard)
{
	const char *flags[] = {
		"Read-only",
		"Login required",
		"PRN generation",
		"EID compliant"
	};
	int i, count = 0;

	assert(mycard != NULL);
	printf("PKCS#15 Card [%s]:\n", mycard->tokeninfo->label);
	printf("\tVersion        : %d\n", mycard->tokeninfo->version);
	printf("\tSerial number  : %s\n", mycard->tokeninfo->serial_number);
	printf("\tManufacturer ID: %s\n", mycard->tokeninfo->manufacturer_id);
	if (mycard->tokeninfo->preferred_language)
		printf("\tLanguage       : %s\n", mycard->tokeninfo->preferred_language);
	printf("\tFlags          : ");
	for (i = 0; i < 4; i++) {
		if ((mycard->tokeninfo->flags >> i) & 1) {
			if (count)
				printf(", ");
			printf("%s", flags[i]);
			count++;
		}
	}
	printf("\n");
}

static void print_pin(const struct sc_pkcs15_object *obj)
{
	const char *pin_flags[] =
	{
		"case-sensitive", "local", "change-disabled",
		"unblock-disabled", "initialized", "needs-padding",
		"unblockingPin", "soPin", "disable_allowed",
		"integrity-protected", "confidentiality-protected",
		"exchangeRefData"
	};
	struct sc_pkcs15_auth_info *pin;
	const int pf_count = sizeof(pin_flags) / sizeof(pin_flags[0]);
	int i;

	pin = (struct sc_pkcs15_auth_info *) obj->data;
	printf("\tAuth ID     : %s\n", sc_pkcs15_print_id(&pin->auth_id));
	if (pin->auth_type == SC_PKCS15_PIN_AUTH_TYPE_PIN)   {
		printf("\tFlags       : [0x%02X]", pin->attrs.pin.flags);
		for (i = 0; i < pf_count; i++)
			if (pin->attrs.pin.flags & (1 << i)) {
				printf(", %s", pin_flags[i]);
			}
		printf("\n");
		printf("\tLength      : min_len:%lu, max_len:%lu, stored_len:%lu\n",
			(unsigned long) pin->attrs.pin.min_length,
			(unsigned long) pin->attrs.pin.max_length,
			(unsigned long) pin->attrs.pin.stored_length);
		printf("\tPad char    : 0x%02X\n", pin->attrs.pin.pad_char);
		printf("\tReference   : %d\n", pin->attrs.pin.reference);
		printf("\tEncoding    : ");
		switch (pin->attrs.pin.type) {
		case SC_PKCS15_PIN_TYPE_BCD:
			printf("BCD\n"); break;
		case SC_PKCS15_PIN_TYPE_ASCII_NUMERIC:
			printf("ASCII-numeric\n"); break;
		case SC_PKCS15_PIN_TYPE_UTF8:
			printf("UTF8\n"); break;
		case SC_PKCS15_PIN_TYPE_HALFNIBBLE_BCD:
			printf("half-nibble BCD\n"); break;
		case SC_PKCS15_PIN_TYPE_ISO9564_1:
			printf("ISO 9564-1\n"); break;
		default:
			printf("[encoding %d]\n", pin->attrs.pin.type);
		}
	}
	if (pin->path.len)
		printf("\tPath        : %s\n", sc_print_path(&pin->path));
	if (pin->tries_left >= 0)
		printf("\tTries left  : %d\n", pin->tries_left);
}

static void print_prkey(const struct sc_pkcs15_object *obj)
{
	int i;
	size_t j;
	const char *usages[] =
	{
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages) / sizeof(usages[0]);
	const char *access_flags[] =
	{
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags) / sizeof(access_flags[0]);
	struct sc_pkcs15_prkey_info *prkey;

	prkey = (struct sc_pkcs15_prkey_info *) obj->data;

	printf("\tUsage       : [0x%X]", prkey->usage);
	for (i = 0; i < usage_count; i++)
		if (prkey->usage & (1 << i)) {
			printf(", %s", usages[i]);
		}
	printf("\n");
	printf("\tAccess Flags: [0x%X]", prkey->access_flags);
	for (i = 0; i < af_count; i++)
		if (prkey->access_flags & (1 << i)) {
			printf(", %s", access_flags[i]);
		}
	printf("\n");
	if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)
		printf("\tModLength   : %lu\n", 
			(unsigned long) prkey->modulus_length);
	printf("\tKey ref     : %d\n", prkey->key_reference);
	printf("\tNative      : %s\n", prkey->native ? "yes" : "no");
	if (prkey->path.len) {
		printf("\tPath        : ");
		for (j = 0; j < prkey->path.len; j++)
			printf("%02X", prkey->path.value[j]);
		if (prkey->path.type == SC_PATH_TYPE_PATH_PROT)
			printf(" (protected)");
		printf("\n");
	}
	printf("\tID          : %s\n", sc_pkcs15_print_id(&prkey->id));
}

static void print_pubkey(const struct sc_pkcs15_object *obj)
{
	int i;
	size_t j;
	const char *usages[] =
	{
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages) / sizeof(usages[0]);
	const char *access_flags[] =
	{
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags) / sizeof(access_flags[0]);
	struct sc_pkcs15_pubkey_info *pubkey;

	pubkey = (struct sc_pkcs15_pubkey_info *) obj->data;

	printf("\tUsage       : [0x%X]", pubkey->usage);
	for (i = 0; i < usage_count; i++)
		if (pubkey->usage & (1 << i)) {
			printf(", %s", usages[i]);
		}
	printf("\n");
	printf("\tAccess Flags: [0x%X]", pubkey->access_flags);
	for (i = 0; i < af_count; i++)
		if (pubkey->access_flags & (1 << i)) {
			printf(", %s", access_flags[i]);
		}
	printf("\n");
	if (obj->type == SC_PKCS15_TYPE_PUBKEY_RSA)
		printf("\tModLength   : %lu\n",
			(unsigned long) pubkey->modulus_length);
	printf("\tKey ref     : %d\n", pubkey->key_reference);
	printf("\tNative      : %s\n", pubkey->native ? "yes" : "no");
	printf("\tPath        : ");
	for (j = 0; j < pubkey->path.len; j++)
		printf("%02X", pubkey->path.value[j]);
	printf("\n");
	printf("\tID          : %s\n", sc_pkcs15_print_id(&pubkey->id));
}

static void print_cert_x509(const struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_cert_info *cert;

	cert = (struct sc_pkcs15_cert_info *) obj->data;
	printf("\tAuthority   : %s\n", cert->authority ? "yes" : "no");
	printf("\tPath        : %s\n",
		       	cert->path.len? sc_print_path(&cert->path) : "<direct encoding>");
	printf("\tID          : %s\n", sc_pkcs15_print_id(&cert->id));

	/* XXX original p15dump code would read the certificate
	 * and dump the label */
}

static void print_data_object_summary(const struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_data_info *data_object;
	unsigned i;

	data_object = (struct sc_pkcs15_data_info *) obj->data;
	printf("\tPath        : ");
	for (i = 0; i < data_object->path.len; i++)
		printf("%02X", data_object->path.value[i]);
	printf("\n");
	printf("\tID          : %s\n", sc_pkcs15_print_id(&data_object->id));

	/* XXX original p15dump code would read the data object
	 * and dump the label */
}

void sc_test_print_object(const struct sc_pkcs15_object *obj)
{
	const char *kind;
	void (*printer) (const struct sc_pkcs15_object *);

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		printer = print_pin;
		kind = "PIN";
		break;
	case SC_PKCS15_TYPE_PRKEY_RSA:
		printer = print_prkey;
		kind = "Private RSA key";
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		printer = print_pubkey;
		kind = "Public RSA key";
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		printer = print_prkey;
		kind = "Private DSA key";
		break;
	case SC_PKCS15_TYPE_PUBKEY_DSA:
		printer = print_pubkey;
		kind = "Public DSA key";
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		printer = print_cert_x509;
		kind = "X.509 Certificate";
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		printer = print_data_object_summary;
		kind = "Data Object";
		break;
	default:
		printer = NULL;
		kind = "Something";
		break;
	}

	printf("%s", kind);
	if (obj->label[0])
		printf(" [%.*s]\n", (int) sizeof obj->label, obj->label);
	else
		printf(" (no label)\n");
	printf("\tCom. Flags  : ");
	switch (obj->flags) {
	case 0x01: printf("private\n"); break;
	case 0x02: printf("modifiable\n"); break;
	case 0x03: printf("private, modifiable\n"); break;
	default:   printf("0x%X\n", obj->flags);
	}
	if (obj->auth_id.len)
		printf("\tCom. Auth ID: %s\n", sc_pkcs15_print_id(&obj->auth_id));
	if (obj->user_consent)
		printf("\tUser consent: %u\n", obj->user_consent);

	if (printer)
		printer(obj);
}
