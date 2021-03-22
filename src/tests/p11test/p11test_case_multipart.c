/*
 * p11test_case_multipart.c: Multipart Sign & Verify tests (RSA only)
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

#include "p11test_case_multipart.h"

void multipart_tests(void **state) {

	token_info_t *info = (token_info_t *) *state;
	unsigned int i;
	int used, j;
	test_certs_t objects;

	objects.count = 0;
	objects.data = NULL;

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Multipart Sign&Verify");
	for (i = 0; i < objects.count; i++) {
		if (objects.data[i].private_handle == CK_INVALID_HANDLE) {
			debug_print(" [ SKIP %s ] Skip missing private key",
			objects.data[i].id_str);
			continue;
		}
		if (objects.data[i].type == EVP_PK_EC) {
			debug_print(" [ SKIP %s ] EC keys do not support multi-part operations",
			objects.data[i].id_str);
			continue;
		}
		used = 0;
		/* do the Sign&Verify */
		/* XXX some keys do not have appropriate flags, but we can use them
		 * or vice versa */
		//if (objects.data[i].sign && objects.data[i].verify)
			for (j = 0; j < objects.data[i].num_mechs; j++)
				used |= sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]), 32, 1);

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02lX",
			objects.data[i].id_str, objects.data[i].key_type);
		}
	}

	if (objects.count == 0) {
		printf(" [WARN] No objects to display\n");
		return;
	}

	/* print summary */
	printf("[KEY ID] [TYPE] [ SIZE ] [PUBLIC] [SIGN&VERIFY] [LABEL]\n");
	P11TEST_DATA_ROW(info, 3,
		's', "KEY ID",
		's', "MECHANISM",
		's', "MULTIPART SIGN&VERIFY WORKS");
	for (i = 0; i < objects.count; i++) {
		if (objects.data[i].type == EVP_PK_EC)
			continue;
		printf("[%-6s] [%s] [%6lu] [ %s ] [%s%s] [%s]\n",
			objects.data[i].id_str,
			(objects.data[i].key_type == CKK_RSA ? "RSA " :
				objects.data[i].key_type == CKK_EC ? " EC " :
				objects.data[i].key_type == CKK_EC_EDWARDS ? "EC_E" :
				objects.data[i].key_type == CKK_EC_MONTGOMERY ? "EC_M" : " ?? "),
			objects.data[i].bits,
			objects.data[i].verify_public == 1 ? " ./ " : "    ",
			objects.data[i].sign ? "[./] " : "[  ] ",
			objects.data[i].verify ? " [./] " : " [  ] ",
			objects.data[i].label);
		if (objects.data[i].private_handle == CK_INVALID_HANDLE) {
			continue;
		}
		for (j = 0; j < objects.data[i].num_mechs; j++) {
			test_mech_t *mech = &objects.data[i].mechs[j];
			if ((mech->usage_flags & CKF_SIGN) == 0) {
				/* not applicable mechanisms are skipped */
				continue;
			}
			printf("         [ %-20s ] [   %s    ]\n",
				get_mechanism_name(mech->mech),
				mech->result_flags & FLAGS_SIGN_ANY ? "[./]" : "    ");
			if ((mech->result_flags & FLAGS_SIGN_ANY) == 0)
				continue; /* do not export unknown and non-working algorithms */
			P11TEST_DATA_ROW(info, 3,
				's', objects.data[i].id_str,
				's', get_mechanism_name(mech->mech),
				's', mech->result_flags & FLAGS_SIGN_ANY ? "YES" : "");
		}
		printf("\n");
	}
	printf(" Public == Cert ------------^       ^  ^  ^\n");
	printf(" Sign Attribute --------------------'  |  |\n");
	printf(" Sign&Verify functionality ------------'  |\n");
	printf(" Verify Attribute ------------------------'\n");

	clean_all_objects(&objects);
	P11TEST_PASS(info);
}
