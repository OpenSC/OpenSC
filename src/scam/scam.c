/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "scam.h"
#ifdef ATR_SUPPORT
#include <opensc.h>
#endif

struct scam_framework_ops *scam_frameworks[] =
{
#ifdef HAVE_SCIDI
	&scam_fw_sp,
#endif
#ifdef HAVE_OPENSSL
#ifdef HAVE_LDAP
	&scam_fw_p15_ldap,
#endif
	&scam_fw_p15_eid,
#endif
	NULL
};

int scam_enum_modules(void)
{
	int i = 0;

	for (i = 0;; i++) {
		if (!scam_frameworks[i])
			return i - 1;
	}
	return -1;
}

#ifdef ATR_SUPPORT
const char *scam_get_atr(unsigned int readernum)
{
#define SCAM_MAX_ATR_LEN (SC_MAX_ATR_SIZE * 3)
	static char atr[SCAM_MAX_ATR_LEN];
	struct sc_context *ctx = NULL;
	struct sc_card *card = NULL;
	int r, i, c = 0;

	memset(atr, 0, SCAM_MAX_ATR_LEN);
	r = sc_establish_context(&ctx);
	if (r) {
		return NULL;
	}
	if (readernum >= ctx->reader_count || readernum < 0) {
		sc_destroy_context(ctx);
		return NULL;
	}
	if (sc_detect_card_presence(ctx->reader[readernum], 0) != 1) {
		sc_destroy_context(ctx);
		return NULL;
	}
	r = sc_connect_card(ctx->reader[readernum], 0, &card);
	if (r) {
		sc_destroy_context(ctx);
		return NULL;
	}
	for (i = 0; i < card->atr_len; i++) {
		unsigned char un = card->atr[i] >> 4;
		unsigned char ln = card->atr[i] - un * 0x10;

		if (un < 10) {
			atr[c] = '0' + un;
		} else {
			atr[c] = 'a' + (un - 10);
		}
		c++;
		if (ln < 10) {
			atr[c] = '0' + ln;
		} else {
			atr[c] = 'a' + (ln - 10);
		}
		c++;
		atr[c] = ':';
		c++;
	}
	atr[c] = 0;
	sc_disconnect_card(card, 0);
	sc_destroy_context(ctx);
	return &atr[0];
}

/* Strip of colons from ATR strings and compare them */

static int compareatr(const char *a1, const char *a2)
{
	char *atr1 = NULL, *atr2 = NULL;
	int i, ret = -1;

	if (!a1 || !a2)
		return -1;
	atr1 = malloc(strlen(a1) + 1);
	atr2 = malloc(strlen(a2) + 1);
	if (!atr1 || !atr2) {
		if (atr1)
			free(atr1);
		if (atr2)
			free(atr2);
		return -1;
	}
	memset(atr1, 0, strlen(a1) + 1);
	memset(atr2, 0, strlen(a2) + 1);
	for (i = 0; i < strlen(a1); i++) {
		if (a1[i] != ':') {
			atr1[i] = tolower(a1[i]);
		}
	}
	for (i = 0; i < strlen(a2); i++) {
		if (a2[i] != ':') {
			atr2[i] = tolower(a2[i]);
		}
	}
	ret = strcmp(atr1, atr2);
	free(atr1);
	free(atr2);
	return ret;
}

int scam_select_by_atr(const char *atr)
{
	int i, j;

	if (!atr)
		return -1;
	for (i = 0; scam_frameworks[i]; i++) {
		for (j = 0; scam_frameworks[i]->atrs[j]; j++) {
			if (!compareatr(scam_frameworks[i]->atrs[j], atr)) {
				return i;
				break;
			}
		}
	}
	return -1;
}
#endif

int scam_select_by_name(const char *method)
{
	int i;

	if (!method)
		return -1;
	for (i = 0; scam_frameworks[i]; i++) {
		if (!strcmp(scam_frameworks[i]->name, method)) {
			return i;
			break;
		}
	}
	return -1;
}

const char *scam_name(unsigned int method)
{
	if (method > scam_enum_modules())
		return NULL;
	if (scam_frameworks[method] && scam_frameworks[method]->name) {
		return scam_frameworks[method]->name;
	}
	return NULL;
}

const char *scam_usage(unsigned int method)
{
	if (method > scam_enum_modules())
		return NULL;
	if (scam_frameworks[method] && scam_frameworks[method]->usage) {
		return scam_frameworks[method]->usage();
	}
	return NULL;
}

void scam_handles(unsigned int method, void *ctx1, void *ctx2, void *ctx3)
{
	if (method > scam_enum_modules())
		return;
	if (scam_frameworks[method] && scam_frameworks[method]->handles) {
		scam_frameworks[method]->handles(ctx1, ctx2, ctx3);
	}
}

int scam_init(unsigned int method, int argc, const char **argv)
{
	if (method > scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[method] && scam_frameworks[method]->init) {
		return scam_frameworks[method]->init(argc, argv);
	}
	return SCAM_SUCCESS;
}

const char *scam_pinentry(unsigned int method)
{
	if (method > scam_enum_modules())
		return NULL;
	if (scam_frameworks[method] && scam_frameworks[method]->pinentry) {
		return scam_frameworks[method]->pinentry();
	}
	return NULL;
}

int scam_qualify(unsigned int method, unsigned char *password)
{
	if (method > scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[method] && scam_frameworks[method]->qualify) {
		return scam_frameworks[method]->qualify(password);
	}
	return SCAM_SUCCESS;
}

int scam_auth(unsigned int method, int argc, const char **argv, const char *user, const char *password)
{
	if (method > scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[method] && scam_frameworks[method]->auth) {
		return scam_frameworks[method]->auth(argc, argv, user, password);
	}
	return SCAM_FAILED;
}

void scam_deinit(unsigned int method)
{
	if (method > scam_enum_modules())
		return;
	if (scam_frameworks[method] && scam_frameworks[method]->deinit) {
		scam_frameworks[method]->deinit();
	}
	scam_handles(method, NULL, NULL, NULL);
}

int scam_open_session(unsigned int method, int argc, const char **argv, const char *user)
{
	if (method > scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[method] && scam_frameworks[method]->open_session) {
		return scam_frameworks[method]->open_session(argc, argv, user);
	}
	return SCAM_SUCCESS;
}

int scam_close_session(unsigned int method, int argc, const char **argv, const char *user)
{
	if (method > scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[method] && scam_frameworks[method]->close_session) {
		return scam_frameworks[method]->close_session(argc, argv, user);
	}
	return SCAM_SUCCESS;
}
