/*
 * $Id$
 *
 * Copyright (C) 2001, 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 *  Anna Erika Suortti <asuortti@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "scam.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

static int scam_method = 0;
static char *auth_method = NULL;

static void usage(void)
{
	int i;

	printf("pam_opensc: [options]\n\n");
	printf("Generic options:\n");
	printf(" -h		Show help\n\n");
	for (i = 0; scam_frameworks[i]; i++) {
		if (scam_frameworks[i]->name && scam_frameworks[i]->usage) {
			printf("auth_method[%s]:\n%s\n", scam_frameworks[i]->name, scam_frameworks[i]->usage());
		}
	}
}

#if (defined(PAM_STATIC) && defined(PAM_SM_AUTH)) || !defined(PAM_STATIC)
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	PAM_CONST char *user = NULL, *password = NULL, *tty = NULL, *service = NULL;
	const char *pinentry = NULL;
	unsigned int ctrl = 0;
	int rv = 0, i = 0;

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'h':
			case '?':
				usage();
				return PAM_MODULE_UNKNOWN;
				break;
			}
		}
	}
	ctrl = _set_ctrl(pamh, flags, &auth_method, argc, (const char **) argv);
	scam_method = 0;
	if (auth_method) {
		scam_method = scam_select_by_name(auth_method);
		free(auth_method);
		auth_method = NULL;
	}
	if (scam_method < 0) {
		return PAM_TRY_AGAIN;
	}
	scam_handles(scam_method, pamh, &ctrl, NULL);
	rv = scam_init(scam_method, argc, (const char **) argv);
	if (rv != SCAM_SUCCESS) {
		scam_deinit(scam_method);
		return PAM_TRY_AGAIN;
	}
	pinentry = scam_pinentry(scam_method);

	/* Get the username */
	rv = pam_get_user(pamh, &user, "login: ");
	if (rv == PAM_SUCCESS) {
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a user name. Don't take
		 * any chances here. Require that the username starts with an
		 * alphanumeric character.
		 */
		if (!user || !isalnum((int) *user)) {
			opensc_pam_log(LOG_ERR, pamh, "bad username [%s]\n", user);
			rv = PAM_USER_UNKNOWN;
			scam_deinit(scam_method);
			return rv;
		}
		if (rv == PAM_SUCCESS && on(OPENSC_DEBUG, ctrl)) {
			opensc_pam_log(LOG_DEBUG, pamh, "username [%s] obtained\n", user);
		}
	} else {
		opensc_pam_log(LOG_DEBUG, pamh, "trouble reading username\n");
		if (rv == PAM_CONV_AGAIN) {
			opensc_pam_log(LOG_DEBUG, pamh, "pam_get_user/conv() function is not ready yet\n");
			/* it is safe to resume this function so we translate this
			 * rv to the value that indicates we're happy to resume.
			 */
			rv = PAM_INCOMPLETE;
		}
		scam_deinit(scam_method);
		return rv;
	}
	/* Check tty */
	rv = pam_get_item(pamh, PAM_TTY, (void *) &tty);
	/* Get the name of the service */
	rv = pam_get_item(pamh, PAM_SERVICE, (PAM_CONST void **) &service);
	if (rv != PAM_SUCCESS) {
		scam_deinit(scam_method);
		return rv;
	}
	/* get this user's authentication token */
	rv = _read_password(pamh, ctrl, NULL, (PAM_CONST char *) (pinentry ? pinentry : DEFAULT_PINENTRY), NULL, _PAM_AUTHTOK, &password);
	if (rv != PAM_SUCCESS) {
		if (rv != PAM_CONV_AGAIN) {
			opensc_pam_log(LOG_CRIT, pamh, "auth could not identify password for [%s]\n", user);
		} else {
			opensc_pam_log(LOG_DEBUG, pamh, "conversation function is not ready yet\n");
			/*
			 * it is safe to resume this function so we translate this
			 * rv to the value that indicates we're happy to resume.
			 */
			rv = PAM_INCOMPLETE;
		}
		user = NULL;
		scam_deinit(scam_method);
		return rv;
	}
	if (!user) {
		scam_deinit(scam_method);
		return PAM_USER_UNKNOWN;
	}
	if (!tty) {
		tty = "";
	}
	if (!service || !password) {
		scam_deinit(scam_method);
		return PAM_AUTH_ERR;
	}
#if 1
	/* No remote logins allowed through xdm */
	if ((!strcmp(service, "xdm") &&
	     strcmp(tty, ":0"))) {
		log_message("User %s (tty %s) tried remote login through service %s, permission denied.\n", user, tty, service);
		scam_deinit(scam_method);
		return PAM_PERM_DENIED;
	}
#endif

	rv = scam_qualify(scam_method, (unsigned char *) password);
	if (rv != SCAM_SUCCESS) {
		pam_set_item(pamh, PAM_AUTHTOK, password);
		scam_deinit(scam_method);
		return PAM_TRY_AGAIN;
	}
	rv = scam_auth(scam_method, argc, (const char **) argv, user, password);
	scam_deinit(scam_method);
	if (rv != SCAM_SUCCESS) {
		opensc_pam_log(LOG_INFO, pamh, "Authentication failed for %s at %s.\n", user, tty);
		return PAM_AUTH_ERR;
	}
	opensc_pam_log(LOG_INFO, pamh, "Authentication successful for %s at %s.\n", user, tty);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      const char **argv)
{
	return PAM_SUCCESS;
}
#endif

#if (defined(PAM_STATIC) && defined(PAM_SM_ACCOUNT)) || !defined(PAM_STATIC)
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
				const char **argv)
{
	return PAM_SUCCESS;
}
#endif

#if (defined(PAM_STATIC) && defined(PAM_SM_SESSION)) || !defined(PAM_STATIC)
PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	PAM_CONST char *user = NULL, *service = NULL;
	unsigned int ctrl = 0;
	int rv = 0;

	ctrl = _set_ctrl(pamh, flags, &auth_method, argc, argv);
	scam_method = 0;
	if (auth_method) {
		scam_method = scam_select_by_name(auth_method);
		free(auth_method);
		auth_method = NULL;
	}
	if (scam_method < 0) {
		return PAM_SESSION_ERR;
	}
	rv = pam_get_item(pamh, PAM_USER, (void *) &user);
	if (!user || rv != PAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "open_session - error recovering username\n");
		return PAM_SESSION_ERR;		/* How did we get authenticated with no username?! */
	}
	if (on(OPENSC_DEBUG, ctrl))
		opensc_pam_log(LOG_INFO, pamh, "Pam user name %s\n", user);
	rv = pam_get_item(pamh, PAM_SERVICE, (void *) &service);
	if (!service || rv != PAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "open_session - error recovering service\n");
		return PAM_SESSION_ERR;
	}
	rv = scam_open_session(scam_method, argc, (const char **) argv, user);
	if (rv != SCAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "open_session - scam_open_session failed\n");
		return PAM_SESSION_ERR;
	}
	opensc_pam_log(LOG_INFO, pamh, "session opened for user %s by %s(uid=%d)\n", user, GetLogin() == NULL ? "" : GetLogin(), getuid());
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
				    const char **argv)
{
	PAM_CONST char *user = NULL, *service = NULL;
	unsigned int ctrl = 0;
	int rv = 0;

	ctrl = _set_ctrl(pamh, flags, &auth_method, argc, argv);
	scam_method = 0;
	if (auth_method) {
		scam_method = scam_select_by_name(auth_method);
		free(auth_method);
		auth_method = NULL;
	}
	if (scam_method < 0) {
		return PAM_SESSION_ERR;
	}
	rv = pam_get_item(pamh, PAM_USER, (void *) &user);
	if (!user || rv != PAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "close_session - error recovering username\n");
		return PAM_SESSION_ERR;		/* How did we get authenticated with no username?! */
	}
	rv = pam_get_item(pamh, PAM_SERVICE, (void *) &service);
	if (!service || rv != PAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "close_session - error recovering service\n");
		return PAM_SESSION_ERR;
	}
	rv = scam_close_session(scam_method, argc, (const char **) argv, user);
	if (rv != SCAM_SUCCESS) {
		opensc_pam_log(LOG_CRIT, pamh, "open_session - scam_close_session failed\n");
		return PAM_SESSION_ERR;
	}
	opensc_pam_log(LOG_INFO, pamh, "session closed for user %s\n", user);
	return PAM_SUCCESS;
}
#endif

#if (defined(PAM_STATIC) && defined(PAM_SM_PASSWORD)) || !defined(PAM_STATIC)
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
				const char **argv)
{
	return PAM_SUCCESS;
}
#endif

#ifdef PAM_STATIC
struct pam_module _pam_opensc_modstruct =
{
	"pam_opensc",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL,
};
#endif

#ifdef PAMTEST

extern int misc_conv(int num_msg, PAM_CONST struct pam_message **msgm, struct pam_response **response, void *appdata_ptr);

int main(int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv conv =
	{
		misc_conv,
		NULL
	};
	int flags = 0, count = 3, rv = PAM_AUTH_ERR;
	const char *user = getenv("USER");

	if (!user) {
		printf("No $USER found.\n");
	}
	do {
		rv = pam_start("test", user, &conv, &pamh);
		fprintf(stderr, "[%02i] pam_start: %d\n", count, rv);
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_authenticate(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_authenticate: %d\n", count, rv);
		}
		if (rv == PAM_MODULE_UNKNOWN) {
			pam_end(pamh, rv);
			break;
		}
		if (rv == PAM_SUCCESS) {
			fprintf(stderr, "Authenticated\n");
		} else {
			fprintf(stderr, "Authentication failed.\n");
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_acct_mgmt(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_acct_mgmt: %d\n", count, rv);
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_open_session(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_open_session: %d\n", count, rv);
		}
		if (rv == PAM_SUCCESS) {
			rv = pam_sm_close_session(pamh, flags, argc, (const char **) argv);
			fprintf(stderr, "[%02i] pam_sm_close_session: %d\n", count, rv);
		}
		if (pam_end(pamh, rv) != PAM_SUCCESS) {
			pamh = NULL;
		}
		count--;
		rv = PAM_AUTH_ERR;
	} while (count > 0);
	return 0;
}

#endif
