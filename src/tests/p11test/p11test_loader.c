/*
 * p11test_loader.c: Library loader for PKCS#11 test suite
 *
 * Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>
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

#include "p11test_loader.h"

void *pkcs11_so;

int get_slot_with_card(token_info_t * info)
{
    CK_SLOT_ID_PTR slot_list;
    CK_SLOT_ID slot_id;
    CK_ULONG slot_count = 0;
    CK_RV rv;
    int error = 0;
    unsigned int i;

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    /* Get slot list for memory allocation */
    rv = function_pointer->C_GetSlotList(0, NULL_PTR, &slot_count);

    if ((rv == CKR_OK) && (slot_count > 0)) {
        slot_list = malloc(slot_count * sizeof (CK_SLOT_ID));

        if (slot_list == NULL) {
            fprintf(stderr, "System error: unable to allocate memory\n");
            return 1;
        }

        /* Get the slot list for processing */
        rv = function_pointer->C_GetSlotList(0, slot_list, &slot_count);
        if (rv != CKR_OK) {
            fprintf(stderr, "GetSlotList failed: unable to get slot count.\n");
            error = 1;
            goto cleanup;
        }
    } else {
        fprintf(stderr, "GetSlotList failed: unable to get slot list.\n");
        return 1;
    }

	/* Find a slot capable of specified mechanism */
	for (i = 0; i < slot_count; i++) {
		CK_SLOT_INFO slot_info;
		slot_id = slot_list[i];

		rv = function_pointer->C_GetSlotInfo(slot_id, &slot_info);
		if (rv != CKR_OK)
			continue;

		if (info->slot_id == slot_id) {
			if (info->slot_id == slot_list[i]) { /* explicitly specified slot */
				debug_print("Manually selected slot %lu (%s a token)\n", info->slot_id,
				    ((slot_info.flags & CKF_TOKEN_PRESENT) ? "with" : "without"));
				goto cleanup;
			}
		}

		if (slot_info.flags & CKF_TOKEN_PRESENT) {
			/* first found slot if not specified */
			if (info->slot_id == (unsigned long) -1) {
				info->slot_id = slot_id;
				goto cleanup;
			}
		}
	}
	error = 1;
	fprintf(stderr, "No slot with card inserted or the selected slot does not exist\n");

    cleanup:
    if (slot_list) {
        free(slot_list);
    }

    return error;
}

int load_pkcs11_module(token_info_t * info, const char* path_to_pkcs11_library) {
	CK_RV rv;
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = 0;

    if(strlen(path_to_pkcs11_library) == 0) {
        fprintf(stderr, "You have to specify path to PKCS#11 library.");
        return 1;
    }

    pkcs11_so = dlopen(path_to_pkcs11_library, RTLD_NOW);

    if (!pkcs11_so) {
        fprintf(stderr, "Error loading pkcs#11 so: %s\n", dlerror());
        return 1;
    }

    C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(pkcs11_so, "C_GetFunctionList");

    if (!C_GetFunctionList) {
        fprintf(stderr, "Could not get function list: %s\n", dlerror());
        return 1;
    }

    rv = C_GetFunctionList(&info->function_pointer);
    if (CKR_OK != rv) {
        fprintf(stderr, "C_GetFunctionList call failed: 0x%.8lX", rv);
        return 1;
    }

    rv = info->function_pointer->C_Initialize(NULL_PTR);

    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize: Error = 0x%.8lX\n", rv);
        return 1;
    }

    if (get_slot_with_card(info)) {
        fprintf(stderr, "There is no card present in reader.\n");
        info->function_pointer->C_Finalize(NULL_PTR);
        return 1;
    }

    info->function_pointer->C_Finalize(NULL_PTR);
    return 0;
}

void close_pkcs11_module() {
    if(pkcs11_so)
        dlclose(pkcs11_so);
}

