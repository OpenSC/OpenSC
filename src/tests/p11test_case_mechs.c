/*
 * p11test_case_mechs.c: Check mechanisms supported by token
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#include "p11test_case_mechs.h"

void supported_mechanisms_test(void **state) {
	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

	CK_RV rv;
	CK_ULONG mechanism_count, i;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_MECHANISM_INFO_PTR mechanism_info;

	rv = function_pointer->C_GetMechanismList(info->slot_id, NULL_PTR,
		&mechanism_count);
	if ((rv == CKR_OK) && (mechanism_count > 0)) {
		mechanism_list = (CK_MECHANISM_TYPE_PTR)
			malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE));
		rv = function_pointer->C_GetMechanismList(info->slot_id,
			mechanism_list, &mechanism_count);
		if (rv != CKR_OK) {
			free(mechanism_list);
			function_pointer->C_Finalize(NULL_PTR);
			fail_msg("Could not get mechanism list!\n");
		}

		mechanism_info = (CK_MECHANISM_INFO_PTR)
			malloc(mechanism_count * sizeof(CK_MECHANISM_INFO));

		for (i = 0; i < mechanism_count; i++) {
			CK_MECHANISM_TYPE mechanism_type = mechanism_list[i];
			rv = function_pointer->C_GetMechanismInfo(info->slot_id,
				mechanism_type, &mechanism_info[i]);
			if (rv != CKR_OK)
				continue;

			/* store mechanisms list for later tests */

			/* Assume RSA mechanisms provide both SIGN and VERIFY flags
			 * rather than list all of them
			 */
			if ((mechanism_info[i].flags & (CKF_SIGN | CKF_VERIFY)) != 0
					&& mechanism_list[i] != CKM_RSA_X_509 // XXX skip so far
					&& mechanism_list[i] != CKM_ECDSA
					&& mechanism_list[i] != CKM_ECDSA_SHA1) {
				if (token.num_rsa_mechs < MAX_MECHS)
					token.rsa_mechs[token.num_rsa_mechs++].mech = mechanism_list[i];
				else
					fail_msg("Too many RSA mechanisms (%d)", MAX_MECHS);
			}
			/* We list all known EC mechanisms */
			if (mechanism_list[i] == CKM_ECDSA_SHA1
					|| mechanism_list[i] == CKM_ECDSA) {
				if (token.num_ec_mechs < MAX_MECHS)
					token.ec_mechs[token.num_ec_mechs++].mech = mechanism_list[i];
				else
					fail_msg("Too many EC mechanisms (%d)", MAX_MECHS);
			}
			if ((mechanism_info[i].flags & CKF_GENERATE_KEY_PAIR) != 0) {
				if (token.num_keygen_mechs < MAX_MECHS)
					token.keygen_mechs[token.num_keygen_mechs++].mech = mechanism_list[i];
				else
					fail_msg("Too many KEYGEN mechanisms (%d)", MAX_MECHS);
			}
		}

		printf("[      MECHANISM      ] [ KEY SIZE ] [  FLAGS   ]\n");
		printf("[        CKM_*        ] [ MIN][ MAX] [          ]\n");
		for (i = 0; i < mechanism_count; i++) {
			printf("[%-21s] [%4lu][%4lu] [%10s]",
				get_mechanism_name(mechanism_list[i]),
				mechanism_info[i].ulMinKeySize,
				mechanism_info[i].ulMaxKeySize,
				get_mechanism_flag_name(mechanism_info[i].flags));
			for (CK_FLAGS j = 1; j <= CKF_EC_COMPRESS; j = j<<1)
				if ((mechanism_info[i].flags & j) != 0)
					printf(" %s", get_mechanism_flag_name(j));
			printf("\n");
		}
		free(mechanism_list);
		free(mechanism_info);
	}
}

