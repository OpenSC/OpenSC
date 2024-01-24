/*
 * p11test_case_usage.c: Check if the usage flags are sane
 *
 * Copyright (C) 2016, 2017 Red Hat, Inc.
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
#include "p11test_case_usage.h"

void usage_test(void **state) {
	unsigned int i;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;
	test_certs_t objects;

	test_certs_init(&objects);

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	debug_print("Check if the usage flags are sane.\n");
	for (i = 0; i < objects.count; i++) {
		/* Ignore if there is missing private key */
		if (objects.data[i].private_handle == CK_INVALID_HANDLE)
			continue;

		/* The usage flags are paired */
		if (objects.data[i].sign && !objects.data[i].verify) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] If Sign is set, Verify should be set too.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].decrypt && !objects.data[i].encrypt) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] If Decrypt is set, Encrypt should be set too.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].unwrap && !objects.data[i].wrap) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] If Unwrap is set, Wrap should be set too.\n",
			    objects.data[i].id_str);
		}
		if (objects.data[i].derive_pub != objects.data[i].derive_priv) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Derive should be set on both private and public part.\n",
			    objects.data[i].id_str);
		}

		/* We have at least one usage flag for every key group */
		if (! objects.data[i].sign       && ! objects.data[i].verify &&
		    ! objects.data[i].encrypt    && ! objects.data[i].decrypt &&
		    ! objects.data[i].wrap       && ! objects.data[i].unwrap &&
		    ! objects.data[i].derive_pub && ! objects.data[i].derive_priv) {
			errors++;
			fprintf(stderr, " [ ERROR %s ] Key group should have at least one usage flag.\n",
			    objects.data[i].id_str);
		}
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ] [PUBLIC] [SIGN&VERIFY] [ENC&DECRYPT] [WRAP&UNWR] [ DERIVE ] [ALWAYS_AUTH]\n");
	P11TEST_DATA_ROW(info, 14,
		's', "KEY ID",
		's', "LABEL",
		's', "TYPE",
		's', "BITS",
		's', "VERIFY PUBKEY",
		's', "SIGN",
		's', "VERIFY",
		's', "ENCRYPT",
		's', "DECRYPT",
		's', "WRAP",
		's', "UNWRAP",
		's', "DERIVE PUBLIC",
		's', "DERIVE PRIVATE",
		's', "ALWAYS AUTH");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];

		printf("\n[%-6s] [%s]\n", o->id_str, o->label);

		/* Ignore if there is missing private key */
		if (objects.data[i].private_handle == CK_INVALID_HANDLE)
			continue;

		printf("[ %s ] [%6lu] [ %s ] [%s%s] [%s%s] [%s %s] [%s%s] [    %s   ]\n",
				(o->key_type == CKK_RSA ? "RSA " : o->key_type == CKK_EC ? " EC "
						: o->key_type == CKK_EC_EDWARDS ? "EC_E"
						: o->key_type == CKK_EC_MONTGOMERY ? "EC_M"
						: o->key_type == CKK_AES ? "AES "
						: o->key_type == CKK_GENERIC_SECRET ? "GEN "
											: " ?? "),
				o->bits,
				o->verify_public == 1 ? " ./ " : "    ",
				o->sign ? "[./] " : "[  ] ",
				o->verify ? " [./] " : " [  ] ",
				o->encrypt ? "[./] " : "[  ] ",
				o->decrypt ? " [./] " : " [  ] ",
				o->wrap ? "[./]" : "[  ]",
				o->unwrap ? "[./]" : "[  ]",
				o->derive_pub ? "[./]" : "[  ]",
				o->derive_priv ? "[./]" : "[  ]",
				o->always_auth ? "[./]" : "[  ]");
		P11TEST_DATA_ROW(info, 14,
				's', o->id_str,
				's', o->label,
				's', (o->key_type == CKK_RSA ? "RSA" : o->key_type == CKK_EC ? "EC"
						: o->key_type == CKK_EC_EDWARDS ? "EC_E"
						: o->key_type == CKK_EC_MONTGOMERY ? "EC_M"
						: o->key_type == CKK_AES ? "AES"
						: o->key_type == CKK_GENERIC_SECRET ? "GEN"
										: " ?? "),
				'd', o->bits,
				's', o->verify_public == 1 ? "YES" : "",
				's', o->sign ? "YES" : "",
				's', o->verify ? "YES" : "",
				's', o->encrypt ? "YES" : "",
				's', o->decrypt ? "YES" : "",
				's', o->wrap ? "YES" : "",
				's', o->unwrap ? "YES" : "",
				's', o->derive_pub ? "YES" : "",
				's', o->derive_priv ? "YES" : "",
				's', o->always_auth ? "YES" : "");
	}
	printf(" Public == Cert -----^       ^-----^       ^-----^       ^----^      ^---^\n");
	printf(" Sign & Verify Attributes ------'             |            |           |\n");
	printf(" Encrypt & Decrypt Attributes ----------------'            |           |\n");
	printf(" Wrap & Unwrap Attributes ---------------------------------'           |\n");
	printf(" Public and Private key Derive Attributes -----------------------------'\n");

	clean_all_objects(&objects);
	if (errors > 0)
		P11TEST_FAIL(info, "Not all the usage flags were successfully verified. See the verbose log.");
	P11TEST_PASS(info);
}
