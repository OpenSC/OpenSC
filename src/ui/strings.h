/*
 * strings.c: default UI strings
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
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

#ifndef _SC_STRINGS_H
#define _SC_STRINGS_H

#include "libopensc/pkcs15.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ui_str {
	MD_PINPAD_DLG_TITLE,
	MD_PINPAD_DLG_MAIN,
	MD_PINPAD_DLG_CONTENT_USER,
	MD_PINPAD_DLG_CONTENT_ADMIN,
	MD_PINPAD_DLG_EXPANDED,
	MD_PINPAD_DLG_CONTROL_COLLAPSED,
	MD_PINPAD_DLG_CONTROL_EXPANDED,
	MD_PINPAD_DLG_ICON,
	MD_PINPAD_DLG_CANCEL,
    NOTIFY_CARD_INSERTED,
    NOTIFY_CARD_INSERTED_TEXT,
    NOTIFY_CARD_REMOVED,
    NOTIFY_CARD_REMOVED_TEXT,
    NOTIFY_PIN_GOOD,
    NOTIFY_PIN_GOOD_TEXT,
    NOTIFY_PIN_BAD,
    NOTIFY_PIN_BAD_TEXT,
	MD_PINPAD_DLG_CONTENT_USER_SIGN,
    NOTIFY_EXIT,
	MD_PINPAD_DLG_VERIFICATION,
};

const char *ui_get_str(struct sc_context *ctx, struct sc_atr *atr,
	   	struct sc_pkcs15_card *p15card, enum ui_str id);

#ifdef __cplusplus
}
#endif

#endif
