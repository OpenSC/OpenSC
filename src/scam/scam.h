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

#ifdef HAVE_CONFIH_H
#include <config.h>
#endif
#if defined(HAVE_PAM)
#include "pam_support.h"
#elif defined(HAVE_OSF_SIA)
#include "sia_support.h"
#endif

#define SCAM_FAILED	1
#define SCAM_SUCCESS	0

/* FIXME: Selecting the right authentication method by ATR needs some
 * more work, configuration file support, support for EMV cards, etc.
 */
#undef ATR_SUPPORT

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
	/* Set handles for specific authentication methods, PAM, SIA, ... */
	void (*handles) (void *ctx1, void *ctx2, void *ctd3);
	/* Print message to screen using handles defined above */
	/* For generic errors and messages that the user might */
	/* want to read. For internal use only. */
	void (*printmsg) (char *str,...);
	/* Log message to syslog, specific log file, ... */
	/* For fatal errors and messages that the system */
	/* administrator might want to read. For internal use only. */
	void (*logmsg) (char *str,...);
	/* Establish a connection to the resource manager, etc. */
	int (*init) (int argc, const char **argv);
	/* Return a pin entry string for conversation functions */
	const char *(*pinentry) (void);
	/* Qualify password - is the password actually a PIN or not */
	/* Speeds up the authentication process with normal passwords */
	int (*qualify) (unsigned char *password);
	/* Authentication function */
	int (*auth) (int argc, const char **argv, const char *user, const char *password);
	/* Close established connections, free memory, etc. */
	void (*deinit) (void);
	/* Open session after authentication */
	int (*open_session) (int argc, const char **argv, const char *user);
	/* Close session */
	int (*close_session) (int argc, const char **argv, const char *user);
};

extern struct scam_framework_ops scam_fw_sp;
extern struct scam_framework_ops scam_fw_p15_eid;
extern struct scam_framework_ops scam_fw_p15_ldap;

extern struct scam_framework_ops *scam_frameworks[];

extern int scam_enum_modules(void);

#ifdef ATR_SUPPORT
extern const char *scam_get_atr(unsigned int readernum);
extern int scam_select_by_atr(const char *atr);
#endif
extern int scam_select_by_name(const char *method);

extern const char *scam_name(unsigned int method);
extern const char *scam_usage(unsigned int method);
extern void scam_handles(unsigned int method, void *ctx1, void *ctx2, void *ctx3);
extern int scam_init(unsigned int method, int argc, const char **argv);
extern const char *scam_pinentry(unsigned int method);
extern int scam_qualify(unsigned int method, unsigned char *password);
extern int scam_auth(unsigned int method, int argc, const char **argv, const char *user, const char *password);
extern void scam_deinit(unsigned int method);
extern int scam_open_session(unsigned int method, int argc, const char **argv, const char *user);
extern int scam_close_session(unsigned int method, int argc, const char **argv, const char *user);

#ifdef __cplusplus
}
#endif
#endif
