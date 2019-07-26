/*
 * p11test_helpers.c: Test suite for PKCS#11 API: Supporting functions
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

#include "p11test_helpers.h"
#include "p11test_loader.h"

int
open_session(token_info_t *info)
{
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
	CK_RV rv;

	rv = function_pointer->C_OpenSession(info->slot_id,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
		&info->session_handle);

	if (rv != CKR_OK) {
		return 1;
	}

	debug_print("Session was successfully created");
	return 0;
}

int
initialize_cryptoki(token_info_t *info)
{
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
	CK_RV rv;

	rv = function_pointer->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) {
		fprintf(stderr, "Could not initialize CRYPTOKI!\n");
		return 1;
	}

	if (get_slot_with_card(info)) {
		function_pointer->C_Finalize(NULL_PTR);
		fprintf(stderr, "There is no card present in reader.\n");
		return 1;
	}

	return 0;
}

int token_initialize(void **state)
{
	token_info_t *info = (token_info_t *) *state;
	if (initialize_cryptoki(info)) {
		debug_print("CRYPTOKI couldn't be initialized");
		return 1;
	}
	return 0;
}

void logfile_init(token_info_t *info)
{
	if (token.log.outfile == NULL) {
		return;
	}

	if ((info->log.fd = fopen(token.log.outfile, "w")) == NULL) {
		fail_msg("Couldn't open file for test results.");
		exit(1);
	}
	fprintf(info->log.fd, "{\n\"time\": 0,\n\"results\": [");
	info->log.in_test = 0;
	info->log.first = 1;
}

void logfile_finalize(token_info_t *info)
{
	if (info == NULL || info->log.fd == NULL) {
		return;
	}

	/* Make sure the JSON object for test is closed */
	if (info->log.in_test) {
		fprintf(info->log.fd, ",\n\t\"result\": \"unknown\"\n},");
		info->log.in_test = 0;
	}

	fprintf(info->log.fd, "]\n}\n");
	fclose(info->log.fd);
}

int group_setup(void **state)
{
	token_info_t * info = calloc(sizeof(token_info_t), 1);

	assert_non_null(info);

	info->pin = token.pin;
	info->pin_length = token.pin_length;
	info->interactive = token.interactive;
	info->slot_id = token.slot_id;

	if (load_pkcs11_module(info, token.library_path)) {
		free(info);
		fail_msg("Could not load module!\n");
		exit(1);
	}

	logfile_init(info);

	*state = info;
	return 0;
}

int group_teardown(void **state)
{
	token_info_t *info = (token_info_t *) *state;
	debug_print("Clearing state after group tests!");
	// XXX do not finalize already Finalized
	//if(info && info->function_pointer)
	//	info->function_pointer->C_Finalize(NULL_PTR);

	free(token.library_path);
	free(token.pin);

	logfile_finalize(info);
	free(info);

	close_pkcs11_module();

	return 0;
}

int prepare_token(token_info_t *info)
{
	if (initialize_cryptoki(info)) {
		debug_print("CRYPTOKI couldn't be initialized");
		return 1;
	}

	if (open_session(info)) {
		debug_print("Could not open session to token!");
		return 1;
	}

	return 0;
}

int finalize_token(token_info_t *info)
{
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

	info->session_handle = 0;
	debug_print("Closing all sessions");
	function_pointer->C_CloseAllSessions(info->slot_id);
	debug_print("Finalize CRYPTOKI");
	function_pointer->C_Finalize(NULL_PTR);
	return 0;
}

int user_login_setup(void **state)
{
	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
	CK_RV rv;

	if (prepare_token(info)) {
		fail_msg("Could not prepare token.\n");
		exit(1);
	}

	debug_print("Logging in to the token!");
	rv = function_pointer->C_Login(info->session_handle, CKU_USER,
		token.pin, token.pin_length);

	if (rv != CKR_OK) {
		fail_msg("Could not login to token with user PIN '%s'\n", token.pin);
		exit(1);
	}

	return 0;
}

int after_test_cleanup(void **state)
{
	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

	debug_print("Logging out from token");
	function_pointer->C_Logout(info->session_handle);

	finalize_token(info);
	return 0;
}

int token_setup(void **state)
{
	token_info_t *info = (token_info_t *) *state;

	if (prepare_token(info)) {
		fail_msg("Could not prepare token.\n");
		exit(1);
	}

	return 0;
}

int token_cleanup(void **state)
{
	token_info_t *info = (token_info_t *) *state;

	finalize_token(info);
	return 0;
}

