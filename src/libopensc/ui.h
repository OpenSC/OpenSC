/*
 * User interface layer.
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
 */

#ifndef _SC_UI_H
#define _SC_UI_H

#include <opensc/opensc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sc_ui_get_pin_info {
	const char *	name_hint;	/* PIN/PUK/old PIN etc */
	int		flags;
	unsigned int	min_len, max_len;
} sc_ui_get_pin_info_t;

#define SC_UI_PIN_RETYPE		0x0001	/* new pin, retype */
#define SC_UI_PIN_OPTIONAL		0x0002	/* new pin optional */
#define SC_UI_PIN_CHECK_LENGTH		0x0004	/* check pin length */
#define SC_UI_PIN_MISMATCH_RETRY	0x0008	/* retry if new pin mismatch? */


/*
 * Specify the dialog language, if the backend is localized.
 */
extern int	sc_ui_set_language(sc_context_t *, const char *);

/*
 * Retrieve a PIN from the user.
 *
 * @name	Dialog name, can be used by the dialog backend
 * 		to retrieve additional resources such as help
 * 		texts, icons etc.
 * @prompt	Text prompt that is displayed if there's no
 * 		GUI backend configured.
 * @info	Additional info on the dialog to display.
 * @out		PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 */
extern int	sc_ui_get_pin(sc_context_t *ctx,
				const char *name,
				const char *prompt,
				const sc_ui_get_pin_info_t *info,
				char **out);

/*
 * PIN pair dialog. Can be used for PIN change/unblock, but
 * also to enter a PIN/PUK pair.
 *
 * @name	Dialog name, can be used by the dialog backend
 * 		to retrieve additional resources such as help
 * 		texts, icons etc.
 * @prompt	Text prompt that is displayed if there's no
 * 		GUI backend configured.
 * @old_info	Additional info on the dialog to display.
 * @old_out	PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 * @new_info	Additional info on the dialog to display.
 * @new_out	PIN entered by the user; must be freed.
 * 		NULL if dialog was canceled.
 */
extern int	sc_ui_get_pin_pair(sc_context_t *ctx,
				const char *name,
				const char *prompt,
				const sc_ui_get_pin_info_t *old_info,
				char **old_out,
				const sc_ui_get_pin_info_t *new_info,
				char **new_out);

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
