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
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#include <sys/types.h>
#include "pam_support.h"

void opensc_pam_log(int err, pam_handle_t * pamh, const char *format,...)
{
	char logname[256], *service = NULL;
	va_list args;

	pam_get_item(pamh, PAM_SERVICE, (PAM_CONST void **) &service);
	if (service) {
		strncpy(logname, service, sizeof(logname));
		logname[sizeof(logname) - 1 - strlen("(pam_opensc)")] = '\0';
		strncat(logname, "(pam_opensc)", strlen("(pam_opensc)"));
	} else {
		strncpy(logname, "pam_opensc", sizeof(logname) - 1);
	}

	openlog(logname, LOG_CONS | LOG_PID, LOG_AUTH);
#ifdef HAVE_VSYSLOG
	vsyslog(err, format, args);
#else
	{
		char	buf[256];

		memset(buf, 0, sizeof(buf));
		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);
		va_end(args);
		syslog(err, "%s", buf);
	}
#endif
	closelog();
}

/* this is a front-end for module-application conversations */
int converse(pam_handle_t * pamh, int ctrl, int nargs
	     ,struct pam_message **message
	     ,struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (PAM_CONST void **) &conv);
	if (retval == PAM_SUCCESS) {

		retval = conv->conv(nargs, (PAM_CONST struct pam_message **) message
				    ,response, conv->appdata_ptr);

		if (retval != PAM_SUCCESS && on(OPENSC_DEBUG, ctrl)) {
			opensc_pam_log(LOG_DEBUG, pamh, "conversation failure [%s]"
				       ,pam_strerror(pamh, retval));
		}
	} else if (retval != PAM_CONV_AGAIN) {
		opensc_pam_log(LOG_ERR, pamh
			       ,"couldn't obtain conversation function [%s]"
			       ,pam_strerror(pamh, retval));
	}
	return retval;		/* propagate error status */
}

int opensc_pam_msg(pam_handle_t * pamh, unsigned int ctrl
		   ,int type, PAM_CONST char *text)
{
	int retval = PAM_SUCCESS;

	if (off(OPENSC__QUIET, ctrl)) {
		struct pam_message *pmsg[1], msg[1];
		struct pam_response *resp;
		char *buf = strdup(text);
		int i;

		if (!buf) {
			return PAM_BUF_ERR;
		}
		pmsg[0] = &msg[0];
		for (i = 0; i < strlen(buf); i++) {
			if (buf[i] == '\n') {
				buf[i] = '\0';
			}
		}
		msg[0].msg = buf;
		msg[0].msg_style = type;

		resp = NULL;
		retval = converse(pamh, ctrl, 1, pmsg, &resp);
		free(buf);

		if (resp) {
			_pam_drop_reply(resp, 1);
		}
	}
	return retval;
}

#if 0
static void print_ctrl(unsigned int ctrl)
{
	unsigned int i;

	for (i = 0; i < OPENSC_CTRLS_; i++) {
		if (on(i, ctrl)) {
			printf("ctrl[%02i] = enabled\n", i);
		} else {
			printf("ctrl[%02i] = disabled\n", i);
		}
	}
}
#endif

/*
 * set the control flags for the OPENSC module.
 */
int _set_ctrl(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	unsigned int ctrl;

	ctrl = OPENSC_DEFAULTS;	/* the default selection of options */

	/* set some flags manually */
	if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
		set(OPENSC__IAMROOT, ctrl);
	}
	if (flags & PAM_UPDATE_AUTHTOK) {
		set(OPENSC__UPDATE, ctrl);
	}
	if (flags & PAM_PRELIM_CHECK) {
		set(OPENSC__PRELIM, ctrl);
	}
	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
		set(OPENSC__NONULL, ctrl);
	}
	if (flags & PAM_SILENT) {
		set(OPENSC__QUIET, ctrl);
	}
	/* now parse the arguments to this module */
	while (argc-- > 0) {
		int j;

		for (j = 0; j < OPENSC_CTRLS_; ++j) {
			if (opensc_args[j].token
			    && !strncmp(*argv, opensc_args[j].token, strlen(opensc_args[j].token))) {
				break;
			}
		}

		if (j >= OPENSC_CTRLS_) {
#if 0
			opensc_pam_log(LOG_ERR, pamh,
				       "unrecognized option [%s]", *argv);
#endif
		} else {
			ctrl &= opensc_args[j].mask;	/* for turning things off */
			ctrl |= opensc_args[j].flag;	/* for turning things on  */
		}
		++argv;		/* step to next argument */
	}

	/* auditing is a more sensitive version of debug */
	if (on(OPENSC_AUDIT, ctrl)) {
		set(OPENSC_DEBUG, ctrl);
	}
	/* return the set of flags */
#if 0
	print_ctrl(ctrl);
#endif
	return ctrl;
}

static void _cleanup(pam_handle_t * pamh, void *x, int error_status)
{
	_pam_delete((char *) x);
}

/* ************************************************************** *
 * Useful non-trivial functions                                   *
 * ************************************************************** */

/*
 * obtain a password from the user
 */
int _read_password(pam_handle_t * pamh
		   ,unsigned int ctrl
		   ,PAM_CONST char *comment
		   ,PAM_CONST char *prompt1
		   ,PAM_CONST char *prompt2
		   ,PAM_CONST char *data_name
		   ,PAM_CONST char **pass)
{
	int authtok_flag, retval;
	PAM_CONST char *item = NULL;
	char *token = NULL;

	/*
	 * which authentication token are we getting?
	 */

	authtok_flag = on(OPENSC__OLD_PASSWD, ctrl) ? PAM_OLDAUTHTOK : PAM_AUTHTOK;

	/*
	 * should we obtain the password from a PAM item ?
	 */
	if (on(OPENSC_TRY_FIRST_PASS, ctrl) || on(OPENSC_USE_FIRST_PASS, ctrl)) {
		retval = pam_get_item(pamh, authtok_flag, (PAM_CONST void **) &item);
		if (retval != PAM_SUCCESS) {
			/* very strange. */
			opensc_pam_log(LOG_ALERT, pamh, "pam_get_item returned error to read-password");
			return retval;
		} else if (item != NULL) {	/* we have a password! */
			*pass = item;
			item = NULL;
			return PAM_SUCCESS;
		} else if (on(OPENSC_USE_FIRST_PASS, ctrl)) {
			return PAM_AUTHTOK_RECOVER_ERR;		/* didn't work */
		} else if (on(OPENSC_USE_AUTHTOK, ctrl)
			   && off(OPENSC__OLD_PASSWD, ctrl)) {
			return PAM_AUTHTOK_RECOVER_ERR;
		}
	}
	/*
	 * getting here implies we will have to get the password from the
	 * user directly.
	 */
	{
		struct pam_message msg[3], *pmsg[3];
		struct pam_response *resp;
		int i, replies;

		/* prepare to converse */
		if (comment != NULL && off(OPENSC__QUIET, ctrl)) {
			pmsg[0] = &msg[0];
			msg[0].msg_style = PAM_TEXT_INFO;
			msg[0].msg = comment;
			i = 1;
		} else {
			i = 0;
		}

		pmsg[i] = &msg[i];
		msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
		msg[i++].msg = prompt1;
		replies = 1;

		if (prompt2 != NULL) {
			pmsg[i] = &msg[i];
			msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
			msg[i++].msg = prompt2;
			++replies;
		}
		/* so call the conversation expecting i responses */
		resp = NULL;
		retval = converse(pamh, ctrl, i, pmsg, &resp);

		if (resp != NULL) {
			/* interpret the response */
			if (retval == PAM_SUCCESS) {	/* a good conversation */
				token = x_strdup(resp[i - replies].resp);
				if (token != NULL) {
					if (replies == 2) {
						/* verify that password entered correctly */
						if (!resp[i - 1].resp || strcmp(token, resp[i - 1].resp)) {
							_pam_delete(token);	/* mistyped */
							retval = PAM_AUTHTOK_RECOVER_ERR;
							opensc_pam_msg(pamh, ctrl, PAM_ERROR_MSG, MISTYPED_PASS);
						}
					}
				} else {
					opensc_pam_log(LOG_NOTICE, pamh, "could not recover authentication token");
				}

			}
			/*
			 * tidy up the conversation (resp_retcode) is ignored
			 * -- what is it for anyway? AGM
			 */

			_pam_drop_reply(resp, i);

		} else {
			retval = (retval == PAM_SUCCESS) ? PAM_AUTHTOK_RECOVER_ERR : retval;
		}
	}

	if (retval != PAM_SUCCESS) {
		if (on(OPENSC_DEBUG, ctrl))
			opensc_pam_log(LOG_DEBUG, pamh,
				       "unable to obtain a password");
		return retval;
	}
	/* 'token' is the entered password */
	if (on(OPENSC_SET_PASS, ctrl)) {
		/* we store this password as an item */

		retval = pam_set_item(pamh, authtok_flag, token);
		_pam_delete(token);	/* clean it up */
		if (retval != PAM_SUCCESS || (retval = pam_get_item(pamh, authtok_flag, (PAM_CONST void **) &item)) != PAM_SUCCESS) {
			opensc_pam_log(LOG_CRIT, pamh, "error manipulating password");
			return retval;
		}
	} else {
		/*
		 * then store it as data specific to this module. pam_end()
		 * will arrange to clean it up.
		 */

		retval = pam_set_data(pamh, data_name, (void *) token, _cleanup);
		if (retval != PAM_SUCCESS) {
			opensc_pam_log(LOG_CRIT, pamh
				       ,"error manipulating password data [%s]"
				       ,pam_strerror(pamh, retval));
			_pam_delete(token);
			return retval;
		}
		item = token;
		token = NULL;	/* break link to password */
	}

	*pass = item;
	item = NULL;		/* break link to password */

	return PAM_SUCCESS;
}

/*
 * Because getlogin() is braindead and sometimes it just
 * doesn't work, we reimplement it here.
 */
char *_get_login(void)
{
  char *user = NULL;
#ifdef HAVE_SETUTENT
  struct utmp *ut = NULL, line;
  static char curr_user[sizeof(ut->ut_user) + 4];
  char *curr_tty = NULL;

  curr_tty = ttyname(0);
  if (curr_tty) {
    curr_tty += 5;
    setutent();
    strncpy(line.ut_line, curr_tty, sizeof line.ut_line);
    if ((ut = getutline(&line))) {
      strncpy(curr_user, ut->ut_user, sizeof(ut->ut_user));
      user = curr_user;
    }
    endutent();
  }
#else
  user = getlogin();
#endif
#if 1
  if (!user) {
    struct passwd *pw_user = getpwuid(geteuid());
    user = pw_user->pw_name;
  }
#endif
  return user;
}
