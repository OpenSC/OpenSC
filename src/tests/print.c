/* Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 PIN code test
 */

#include "sc-test.h"
#include "opensc.h"
#include "opensc-pkcs15.h"
#include <stdio.h>
#include <stdlib.h>

struct sc_pkcs15_card *p15card;

static void
print_pin(const struct sc_pkcs15_object *obj)
{
	const char *pin_flags[] = {
		"case-sensitive", "local", "change-disabled",
		"unblock-disabled", "initialized", "needs-padding",
		"unblockingPin", "soPin", "disable_allowed",
		"integrity-protected", "confidentiality-protected",
		"exchangeRefData"
	};
	struct sc_pkcs15_pin_info *pin;
	const int pf_count = sizeof(pin_flags)/sizeof(pin_flags[0]);
	int i;
	char *p;

	pin = (struct sc_pkcs15_pin_info *) obj->data;
	printf("\tAuth ID     : ");
	sc_pkcs15_print_id(&pin->auth_id);
	printf("\n");
	printf("\tFlags       : [0x%02X]", pin->flags);
	for (i = 0; i < pf_count; i++)
		if (pin->flags & (1 << i)) {
			printf(", %s", pin_flags[i]);
		}
	printf("\n");
	printf("\tLength      : %d..%d\n", pin->min_length, pin->stored_length);
	printf("\tPad char    : 0x%02X\n", pin->pad_char);
	printf("\tReference   : %d\n", pin->reference);
	printf("\tType        : %d\n", pin->type);
	printf("\tPath        : ");
	for (i = 0; i < pin->path.len; i++) {
		printf("%02X", pin->path.value[i]);
		p += 2;
	}
	printf("\n");
}

static void
print_prkey_rsa(const struct sc_pkcs15_object *obj)
{
	int i;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages)/sizeof(usages[0]);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags)/sizeof(access_flags[0]);
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
	printf("\tModLength   : %d\n", prkey->modulus_length);
	printf("\tKey ref     : %d\n", prkey->key_reference);
	printf("\tNative      : %s\n", prkey->native ? "yes" : "no");
	printf("\tPath        : ");
	for (i = 0; i < prkey->path.len; i++)
		printf("%02X", prkey->path.value[i]);
	printf("\n");
	printf("\tID          : ");
	sc_pkcs15_print_id(&prkey->id);
	printf("\n");
}

static void
print_pubkey_rsa(const struct sc_pkcs15_object *obj)
{
	int i;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages)/sizeof(usages[0]);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags)/sizeof(access_flags[0]);
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
	printf("\tModLength   : %d\n", pubkey->modulus_length);
	printf("\tKey ref     : %d\n", pubkey->key_reference);
	printf("\tNative      : %s\n", pubkey->native ? "yes" : "no");
	printf("\tPath        : ");
	for (i = 0; i < pubkey->path.len; i++)
		printf("%02X", pubkey->path.value[i]);
	printf("\n");
	printf("\tID          : ");
	sc_pkcs15_print_id(&pubkey->id);
	printf("\n");
}

static void
print_cert_x509(const struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_cert_info *cert;
	int i;

	cert = (struct sc_pkcs15_cert_info *) obj->data;
	printf("\tAuthority: %s\n", cert->authority ? "yes" : "no");
	printf("\tPath     : ");
	for (i = 0; i < cert->path.len; i++)
		printf("%02X", cert->path.value[i]);
	printf("\n");
	printf("\tID       : ");
	sc_pkcs15_print_id(&cert->id);
	printf("\n");

	/* XXX original p15dump code would read the certificate
	 * and dump the label */
}


void
sc_test_print_object(const struct sc_pkcs15_object *obj)
{
	const char	*kind;
	void		(*printer)(const struct sc_pkcs15_object *);

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		printer = print_pin;
		kind = "PIN";
		break;
	case SC_PKCS15_TYPE_PRKEY_RSA:
		printer = print_prkey_rsa;
		kind = "Private RSA key";
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		printer = print_pubkey_rsa;
		kind = "Public RSA key";
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		printer = print_cert_x509;
		kind = "X.509 Certificate";
		break;
	default:
		printer = NULL;
		kind = "Something";
		break;
	}

	printf("%s", kind);
	if (obj->label[0])
		printf(" [%s]\n", obj->label);
	else
		printf(" (no label)\n");
	printf("\tCom. Flags  : 0x%X\n", obj->flags);
	if (obj->auth_id.len) {
		printf("\tCom. Auth ID: ");
		sc_pkcs15_print_id(&obj->auth_id);
		printf("\n");
	}
	if (printer)
		printer(obj);
}
