/*
 * ui.h: User interface layer
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
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

#ifndef _SC_UI_H
#define _SC_UI_H

#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dialog types
 */
#define SC_UI_USAGE_OTHER		0x0000
#define SC_UI_USAGE_NEW_PIN		0x0001
#define SC_UI_USAGE_UNBLOCK_PIN		0x0002
#define SC_UI_USAGE_CHANGE_PIN		0x0003

/*
 * Dialog flags
 */
#define SC_UI_PIN_RETYPE		0x0001	/* new pin, retype */
#define SC_UI_PIN_OPTIONAL		0x0002	/* new pin optional */
#define SC_UI_PIN_CHECK_LENGTH		0x0004	/* check pin length */
#define SC_UI_PIN_MISMATCH_RETRY	0x0008	/* retry if new pin mismatch? */


/* Hints passed to user interface functions
 * M marks mandatory fields,
 * O marks optional fields
 */
typedef struct sc_ui_hints {
	const char *		prompt;		/* M: cmdline prompt */
	const char *		dialog_name;	/* M: dialog name */
	unsigned int		usage;		/* M: usage hint */
	unsigned int		flags;		/* M: flags */
	sc_card_t *		card;		/* M: card handle */
	struct sc_pkcs15_card *	p15card;	/* O: pkcs15 handle */

	/* We may not have a pkcs15 object yet when we get
	 * here, but we may have an idea of what it's going to
	 * look like. */
	const char *		obj_label;	/* O: object (PIN) label */
	union {
	    struct sc_pkcs15_pin_info *pin;
	} info;
} sc_ui_hints_t;

/*
 * Specify the dialog language, if the backend is localized.
 */
extern int	sc_ui_set_language(sc_context_t *, const char *);

/*
 * Retrieve a PIN from the user.
 *
 * @hints	dialog hints
 * @out		PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 */
extern int	sc_ui_get_pin(sc_ui_hints_t *hints, char **out);

/*
 * PIN pair dialog. Can be used for PIN change/unblock, but
 * also to enter a PIN/PUK pair.
 *
 * @hints	dialog hints
 * @old_out	PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 * @new_out	PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 */
extern int	sc_ui_get_pin_pair(sc_ui_hints_t *hints,
				char **old_out, char **new_out);

/*
 * Other ui functions, not fully spec'ed yet
 */
extern int	sc_ui_display_question(sc_context_t *ctx,
				const char *name,
				const char *prompt);
extern int	sc_ui_display_message(sc_context_t *ctx,
				const char *name,
				const char *message);
extern int	sc_ui_display_error(sc_context_t *ctx,
				const char *msg);
extern int	sc_ui_display_debug(sc_context_t *ctx,
				const char *msg);

#ifdef __cplusplus
}
#endif

#endif /* _SC_UI_H */
