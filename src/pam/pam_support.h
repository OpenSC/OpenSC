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

#ifndef _PAM_SUPPORT_H
#define _PAM_SUPPORT_H

#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY__PAM_MACROS_H
#include <security/_pam_macros.h>
#else
#define x_strdup(s) ((s) ? strdup(s):NULL)
#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)
#define _pam_drop(X) \
do {                 \
    if (X) {         \
        free(X);     \
        X=NULL;      \
    }                \
} while (0)
#define _pam_drop_reply(/* struct pam_response * */ reply, /* int */ replies) \
do {                                              \
    int reply_i;                                  \
                                                  \
    for (reply_i=0; reply_i<replies; ++reply_i) { \
	if (reply[reply_i].resp) {                \
	    _pam_overwrite(reply[reply_i].resp);  \
	    free(reply[reply_i].resp);            \
	}                                         \
    }                                             \
    if (reply)                                    \
	free(reply);                              \
} while (0)
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifdef PAM_SUN_CODEBASE
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#ifndef PAM_CONV_AGAIN
#define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_INCOMPLETE
#define PAM_INCOMPLETE PAM_TRY_AGAIN
#endif
#ifndef PAM_AUTHTOK_RECOVER_ERR
#define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Taken and modified from pam_unix */

extern void opensc_pam_log(int err, pam_handle_t * pamh, const char *format,...);
extern int converse(pam_handle_t * pamh, int ctrl, int nargs, struct pam_message **message, struct pam_response **response);

/*
 * here is the string to inform the user that the new passwords they
 * typed were not the same.
 */

#define DEFAULT_PINENTRY "Enter PIN1: "
#define MISTYPED_PASS "Sorry, passwords do not match"

/* type definition for the control options */
typedef struct {
	const char *token;
	unsigned int mask;	/* shall assume 32 bits of flags */
	unsigned int flag;
} OPENSC_Ctrls;

/*
 * macro to determine if a given flag is on
 */

#define on(x,ctrl)  (opensc_args[x].flag & ctrl)

/*
 * macro to determine that a given flag is NOT on
 */

#define off(x,ctrl) (!on(x,ctrl))

/*
 * macro to turn on/off a ctrl flag manually
 */

#define set(x,ctrl)   (ctrl = ((ctrl)&opensc_args[x].mask)|opensc_args[x].flag)
#define unset(x,ctrl) (ctrl &= ~(opensc_args[x].flag))

/* the generic mask */
#define _ALL_ON_  (~0U)

/* end of macro definitions definitions for the control flags */

/* ****************************************************************** *
 * ctrl flags proper..
 */

/*
 * here are the various options recognized by the opensc module. They
 * are enumerated here and then defined below. Internal arguments are
 * given NULL tokens.
 */

#define OPENSC__OLD_PASSWD          0	/* internal */
#define OPENSC__VERIFY_PASSWD       1	/* internal */
#define OPENSC__IAMROOT             2	/* internal */

#define OPENSC_AUDIT                3	/* print more things than debug..
					   some information may be sensitive */
#define OPENSC_USE_FIRST_PASS       4
#define OPENSC_TRY_FIRST_PASS       5
#define OPENSC_SET_PASS             6	/* set AUTHTOK items */

#define OPENSC__PRELIM              7	/* internal */
#define OPENSC__UPDATE              8	/* internal */
#define OPENSC__NONULL              9	/* internal */
#define OPENSC__QUIET              10	/* internal */
#define OPENSC_USE_AUTHTOK         11	/* insist on reading PAM_AUTHTOK */
#define OPENSC_DEBUG               12	/* send more info to syslog(3) */
#define OPENSC_AUTH_METHOD         13	/* Authentication method */
/* -------------- */
#define OPENSC_CTRLS_              14	/* number of ctrl arguments defined */

static const OPENSC_Ctrls opensc_args[OPENSC_CTRLS_] =
{
/* symbol                  token name          ctrl mask             ctrl     *
 * ----------------------- ------------------- --------------------- -------- */

/* OPENSC__OLD_PASSWD */ 
 {NULL, _ALL_ON_, 01},
/* OPENSC__VERIFY_PASSWD */ 
 {NULL, _ALL_ON_, 02},
/* OPENSC__IAMROOT */ 
 {NULL, _ALL_ON_, 04},
/* OPENSC_AUDIT */ 
 {"audit", _ALL_ON_, 010},
/* OPENSC_USE_FIRST_PASS */ 
 {"use_first_pass", _ALL_ON_, 020},
/* OPENSC_TRY_FIRST_PASS */ 
 {"try_first_pass", _ALL_ON_, 040},
/* OPENSC_SET_PASS */ 
 {"set_pass", _ALL_ON_, 0100},
/* OPENSC__PRELIM */ 
 {NULL, _ALL_ON_, 0200},
/* OPENSC__UPDATE */ 
 {NULL, _ALL_ON_, 0400},
/* OPENSC__NONULL */ 
 {NULL, _ALL_ON_, 01000},
/* OPENSC__QUIET */ 
 {NULL, _ALL_ON_, 02000},
/* OPENSC_USE_AUTHTOK */ 
 {"use_authtok", _ALL_ON_, 04000},
/* OPENSC_DEBUG */ 
 {"debug", _ALL_ON_, 010000},
/* OPENSC_AUTH_METHOD */ 
 {"auth_method=", _ALL_ON_, 020000}
};

#define OPENSC_DEFAULTS  (opensc_args[OPENSC__NONULL].flag)

/* use this to free strings. ESPECIALLY password strings */
#define _pam_delete(xx)		\
{				\
	_pam_overwrite(xx);	\
	_pam_drop(xx);		\
}

extern int opensc_pam_msg(pam_handle_t * pamh, unsigned int ctrl, int type, PAM_CONST char *text);
extern int _set_ctrl(pam_handle_t * pamh, int flags, char **auth_method, int argc, const char **argv);
extern int _read_password(pam_handle_t * pamh
			  ,unsigned int ctrl
			  ,PAM_CONST char *comment
			  ,PAM_CONST char *prompt1
			  ,PAM_CONST char *prompt2
			  ,PAM_CONST char *data_name
			  ,PAM_CONST char **pass);

#define _PAM_AUTHTOK "-OPENSC-PASS"

#ifdef __cplusplus
}
#endif
#endif
