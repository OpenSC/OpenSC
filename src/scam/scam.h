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

#ifndef _SCAM_H
#define _SCAM_H

#ifdef __cplusplus
extern "C" {
#endif

#define SCAM_FAILED	1
#define SCAM_SUCCESS	0

/* FIXME: Selecting the right authentication method by ATR needs some
 * more work, configuration file support, support for EMV cards, etc.
 */
#undef ATR_SUPPORT

typedef struct _scam_context scam_context;

struct _scam_context {
	int method;
	char *auth_method;
	/* Print message to screen, internally used by scam_print_msg */
	void (*printmsg) (scam_context * sctx, char *str);
	/* Log message to syslog, specific log file, etc */
	/* Internally used by scam_log_msg */
	void (*logmsg) (scam_context * sctx, char *str);
	/* Used by printmsg/logmsg */
	void *msg_data;
	/* Private data for scam_framework_ops internals */
	void *method_data;
};

/*
 * Framework abstraction for smart card authentication
 */
struct scam_framework_ops {
	/* Framework name */
	const char *name;
#ifdef ATR_SUPPORT
	/* Supported cards (by ATRs) */
	const char **atrs;
#endif
	/* Return a string for help messages, list known parameters, etc. */
	const char *(*usage) (void);
	/* Establish a connection to the resource manager, etc. */
	int (*init) (scam_context * sctx, int argc, const char **argv);
	/* Return a pin entry string for conversation functions */
	const char *(*pinentry) (scam_context * sctx);
	/* Qualify password - is the password actually a PIN or not */
	/* Speeds up the authentication process with normal passwords */
	int (*qualify) (scam_context * sctx, unsigned char *password);
	/* Authentication function */
	int (*auth) (scam_context * sctx, int argc, const char **argv, const char *user, const char *password);
	/* Close established connections, free memory, etc. */
	void (*deinit) (scam_context * sctx);
	/* Open session after authentication */
	int (*open_session) (scam_context * sctx, int argc, const char **argv, const char *user);
	/* Close session */
	int (*close_session) (scam_context * sctx, int argc, const char **argv, const char *user);
};

extern struct scam_framework_ops scam_fw_p15_eid;
extern struct scam_framework_ops scam_fw_p15_ldap;
extern struct scam_framework_ops *scam_frameworks[];

extern int scam_enum_modules(void);

extern void scam_parse_parameters(scam_context * sctx, int argc, const char **argv);

#ifdef ATR_SUPPORT
extern const char *scam_get_atr(unsigned int readernum);
extern int scam_select_by_atr(const char *atr);
#endif
extern int scam_select_by_name(const char *method);

extern void scam_print_msg(scam_context * sctx, char *str,...);
extern void scam_log_msg(scam_context * sctx, char *str,...);

extern const char *scam_name(scam_context * sctx);
extern const char *scam_usage(scam_context * sctx);
extern void scam_handles(scam_context * sctx, void *ctx1, void *ctx2, void *ctx3);
extern int scam_init(scam_context * sctx, int argc, const char **argv);
extern const char *scam_pinentry(scam_context * sctx);
extern int scam_qualify(scam_context * sctx, unsigned char *password);
extern int scam_auth(scam_context * sctx, int argc, const char **argv, const char *user, const char *password);
extern void scam_deinit(scam_context * sctx);
extern int scam_open_session(scam_context * sctx, int argc, const char **argv, const char *user);
extern int scam_close_session(scam_context * sctx, int argc, const char **argv, const char *user);

#ifdef HAVE_SCIDI
extern struct scam_framework_ops scam_fw_sp;
extern int sp_open_session(scam_context * sctx, int argc, const char **argv, const char *user);
extern int sp_close_session(scam_context * sctx, int argc, const char **argv, const char *user);
#endif

#ifdef __cplusplus
}
#endif
#endif
