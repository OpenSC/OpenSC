/*
 * p11test_case_wait.c: Test slot events (insert / remove)
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
#include "p11test_case_wait.h"

void wait_test(void **state) {

	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_RV rv;
	CK_SLOT_ID slot_id;
	CK_SLOT_INFO slot_info;
	int token_present = 0;

	P11TEST_START(info);
	if (!info->interactive) {
		fprintf(stderr, "To test wait, run in interactive mode (-i switch).\n");
		P11TEST_SKIP(info);
	}

	do {
		printf(" [ Waiting for slot event ... ]\n");

		rv = fp->C_WaitForSlotEvent(0, &slot_id, NULL_PTR);
		if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
			fprintf(stderr, "Function does not support call with blocking wait. Skipping.\n");
			skip();
		} else if (rv != CKR_OK)
			P11TEST_FAIL(info, "C_WaitForSlotEvent: rv = 0x%.8lX\n", rv);

		rv = fp->C_GetSlotInfo(slot_id, &slot_info);
		if (rv != CKR_OK)
			P11TEST_FAIL(info, "C_GetSlotInfo: rv = 0x%.8lX\n", rv);

		token_present = ((slot_info.flags & CKF_TOKEN_PRESENT) != 0);

		printf(" [ Slot %lu ] %s\n", slot_id, slot_info.slotDescription);
		printf("              Status: %s\n",
			token_present ? "Token present": "No token");
	} while (!token_present);
	P11TEST_PASS(info);
}
