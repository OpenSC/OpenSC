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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "scam.h"

#define DIM(v)		(sizeof(v)/(sizeof((v)[0])))

struct scam_framework_ops *scam_frameworks[] =
{
#ifdef HAVE_OPENSSL
	&scam_fw_p15_eid,
#ifdef HAVE_LDAP
#if 0
	&scam_fw_p15_ldap,
#endif
#endif
#endif
	NULL
};

int scam_enum_modules(void)
{
	int count = DIM(scam_frameworks) - 1;

	return (!count ? -1 : count);
}

void scam_parse_parameters(scam_context * sctx, int argc, const char **argv)
{
	const char *auth_method = "auth_method=";

	if (!sctx)
		return;
	while (argc-- > 0) {
		if (!strncmp(*argv, auth_method, strlen(auth_method))) {
			const char *p = *argv + strlen(auth_method);
			size_t len = strlen(p) + 1;

			sctx->auth_method = (char *) realloc(sctx->auth_method, len);
			if (!sctx->auth_method)
				break;
			memset(sctx->auth_method, 0, len);
			strncpy(sctx->auth_method, p, len - 1);
		}
		++argv;
	}
}

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

void scam_print_msg(scam_context * sctx, char *str,...)
{
	va_list ap;
	char buf[128];

	va_start(ap, str);
	memset(buf, 0, 128);
	vsnprintf(buf, 128, str, ap);
	va_end(ap);
	if (sctx && sctx->printmsg)
		sctx->printmsg(sctx, buf);
}

void scam_log_msg(scam_context * sctx, char *str,...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, str);
	memset(buf, 0, 1024);
	vsnprintf(buf, 1024, str, ap);
	va_end(ap);
	if (sctx && sctx->logmsg)
		sctx->logmsg(sctx, buf);
}

const char *scam_name(scam_context * sctx)
{
	if (!sctx)
		return NULL;
	if (sctx->method >= scam_enum_modules())
		return NULL;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->name) {
		return scam_frameworks[sctx->method]->name;
	}
	return NULL;
}

const char *scam_usage(scam_context * sctx)
{
	if (!sctx)
		return NULL;
	if (sctx->method >= scam_enum_modules())
		return NULL;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->usage) {
		return scam_frameworks[sctx->method]->usage();
	}
	return NULL;
}

int scam_init(scam_context * sctx, int argc, const char **argv)
{
	if (!sctx)
		return SCAM_FAILED;
	if (sctx->method >= scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->init) {
		return scam_frameworks[sctx->method]->init(sctx, argc, argv);
	}
	return SCAM_SUCCESS;
}

const char *scam_pinentry(scam_context * sctx)
{
	if (!sctx)
		return NULL;
	if (sctx->method >= scam_enum_modules())
		return NULL;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->pinentry) {
		return scam_frameworks[sctx->method]->pinentry(sctx);
	}
	return NULL;
}

int scam_qualify(scam_context * sctx, unsigned char *password)
{
	if (!sctx)
		return SCAM_FAILED;
	if (sctx->method >= scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->qualify) {
		return scam_frameworks[sctx->method]->qualify(sctx, password);
	}
	return SCAM_SUCCESS;
}

int scam_auth(scam_context * sctx, int argc, const char **argv, const char *user, const char *password)
{
	if (!sctx)
		return SCAM_FAILED;
	if (sctx->method >= scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->auth) {
		return scam_frameworks[sctx->method]->auth(sctx, argc, argv, user, password);
	}
	return SCAM_FAILED;
}

void scam_deinit(scam_context * sctx)
{
	if (!sctx)
		return;
	if (sctx->method >= scam_enum_modules())
		return;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->deinit) {
		scam_frameworks[sctx->method]->deinit(sctx);
	}
}

int scam_open_session(scam_context * sctx, int argc, const char **argv, const char *user)
{
	if (!sctx)
		return SCAM_FAILED;
	if (sctx->method >= scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->open_session) {
		return scam_frameworks[sctx->method]->open_session(sctx, argc, argv, user);
	}
	return SCAM_SUCCESS;
}

int scam_close_session(scam_context * sctx, int argc, const char **argv, const char *user)
{
	if (!sctx)
		return SCAM_FAILED;
	if (sctx->method >= scam_enum_modules())
		return SCAM_FAILED;
	if (scam_frameworks[sctx->method] && scam_frameworks[sctx->method]->close_session) {
		return scam_frameworks[sctx->method]->close_session(sctx, argc, argv, user);
	}
	return SCAM_SUCCESS;
}
