/*
 * notify.h: OpenSC library header file
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

#ifndef _NOTIFY_H
#define _NOTIFY_H

#include "ui/strings.h"

#ifdef __cplusplus
extern "C" {
#endif

void sc_notify_init(void);
void sc_notify_close(void);
void sc_notify(const char *title, const char *text);
void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
        struct sc_pkcs15_card *p15card, enum ui_str id);

#ifdef _WIN32
#include <windows.h>
/* If the code executes in a DLL, `sc_notify_instance_notify` should be
 * initialized before calling `sc_notify_init()`. If not initialized, we're
 * using the HINSTANCE of the EXE */
extern HINSTANCE sc_notify_instance;
/* This is the message created when the user clicks on "exit". */
#define WMAPP_EXIT (WM_APP + 2)
#endif

#ifdef __cplusplus
}
#endif

#endif
