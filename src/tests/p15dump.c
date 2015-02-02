/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 objects test
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "sc-test.h"

static struct sc_pkcs15_card *p15card;

static int dump_objects(const char *what, int type)
{
	struct sc_pkcs15_object **objs;
	int count, i;

	printf("\nEnumerating %s... ", what);
	fflush(stdout);

	if (SC_SUCCESS != sc_lock(card))
		return 1;
	count = sc_pkcs15_get_objects(p15card, type, NULL, 0);
	if (count < 0) {
		printf("failed.\n");
		fprintf(stderr, "Error enumerating %s: %s\n",
			what, sc_strerror(count));
		if (SC_SUCCESS != sc_unlock(card))
			return 1;
		return 1;
	}
	if (count == 0) {
		printf("none found.\n");
		if (SC_SUCCESS != sc_unlock(card))
			return 1;
		return 0;
	}
	printf("%u found.\n", count);

	objs = calloc(count, sizeof(*objs));
	if ((count = sc_pkcs15_get_objects(p15card, type, objs, count)) < 0) {
		fprintf(stderr, "Error enumerating %s: %s\n",
			what, sc_strerror(count));
	} else {
		for (i = 0; i < count; i++)
			sc_test_print_object(objs[i]);
	}
	free(objs);
	if (SC_SUCCESS != sc_unlock(card))
		return 1;
	return (count < 0) ? 1 : 0;
}

static int dump_unusedspace(void)
{
	u8 *buf = NULL;
	size_t buf_len;
	sc_path_t path;
	sc_pkcs15_unusedspace_t *us;
	int r;

	if (p15card->file_unusedspace != NULL)
		path = p15card->file_unusedspace->path;
	else {
		path = p15card->file_app->path;
		sc_append_path_id(&path, (const u8 *) "\x50\x33", 2);
	}
	path.count = -1;

	r = sc_pkcs15_read_file(p15card, &path, &buf, &buf_len);
	if (r < 0) {
		if (r == SC_ERROR_FILE_NOT_FOUND) {
			printf("\nNo EF(UnusedSpace) file\n");
			r = 0;
		}
		else
			printf("\nError reading file \"%s\": %s\n",
				sc_print_path(&path), sc_strerror(r));
		goto err;
	}

	r = sc_pkcs15_parse_unusedspace(buf, buf_len, p15card);
	if (r != 0) {
		printf("\nError parsing EF(UnusedSpace): %s\n", sc_strerror(r));
		goto err;
	}

	if (p15card->unusedspace_list == NULL)
		printf("\nEF(UnusedSpace) file is empty\n");
	else {
		printf("\nContents of EF(UnusedSpace):\n");
		for (us = p15card->unusedspace_list; us != NULL; us = us->next)
		printf("  - path=%s, index=%d, length=%d  -- auth_id = %s\n",
			sc_print_path(&us->path), us->path.index, us->path.count,
			us->auth_id.len == 0 ? "<empty>" : sc_pkcs15_print_id(&us->auth_id));
	}

err:
	if (buf != NULL)
		free(buf);
	return r;
}

int main(int argc, char *argv[])
{
	int i;

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	printf("Looking for a PKCS#15 compatible Smart Card... ");
	fflush(stdout);
	if (SC_SUCCESS != sc_lock(card))
		return 1;
	i = sc_pkcs15_bind(card, NULL, &p15card);
	/* Keep card locked to prevent useless calls to sc_logout */
	if (i) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		return 1;
	}
	printf("found.\n");
	sc_test_print_card(p15card);

	dump_objects("PIN codes", SC_PKCS15_TYPE_AUTH_PIN);
	dump_objects("Private keys", SC_PKCS15_TYPE_PRKEY);
	dump_objects("Public keys", SC_PKCS15_TYPE_PUBKEY);
	dump_objects("X.509 certificates", SC_PKCS15_TYPE_CERT_X509);
	dump_objects("data objects", SC_PKCS15_TYPE_DATA_OBJECT);
	dump_unusedspace();

	sc_pkcs15_unbind(p15card);
	if (SC_SUCCESS != sc_unlock(card))
		return 1;
	sc_test_cleanup();
	return 0;
}
