/*
 * notify.c: Notification implementation
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "notify.h"

#if defined(ENABLE_NOTIFY) && (defined(__APPLE__))

#include "libopensc/internal.h"
#include "libopensc/log.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child = -1;

void sc_notify_init(void)
{
}

void sc_notify_close(void)
{
	if (child > 0) {
		int i, status;
		for (i = 0; child != waitpid(child, &status, WNOHANG); i++) {
			switch (i) {
				case 0:
					kill(child, SIGKILL);
					break;
				case 1:
					kill(child, SIGTERM);
					break;
				default:
					/* SIGTERM was our last resort */
					return;
			}
			usleep(100);
		}
		child = -1;
	}
}

#endif

#if defined(ENABLE_NOTIFY) && defined(_WIN32)

#include "common/compat_strlcpy.h"
#include "invisible_window.h"
#include "wchar_from_char_str.h"
#include <shellapi.h>
#include <shlwapi.h>

// {83C35893-99C6-4600-BFDB-45925C53BDD9}
static const GUID myGUID = { 0x83c35893, 0x99c6, 0x4600, { 0xbf, 0xdb, 0x45, 0x92, 0x5c, 0x53, 0xbd, 0xd9 } };
HINSTANCE sc_notify_instance = NULL;
HWND hwndNotification = NULL;
BOOL delete_icon = TRUE;
#define IDI_SMARTCARD       102
UINT const WMAPP_NOTIFYCALLBACK = WM_APP + 1;
static BOOL RestoreTooltip();

// we need commctrl v6 for LoadIconMetric()
#include <commctrl.h>

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if ((message == WM_DESTROY)
			|| (message == WMAPP_NOTIFYCALLBACK
				&& (LOWORD(lParam) == NIN_BALLOONTIMEOUT
					|| LOWORD(lParam) == NIN_BALLOONUSERCLICK))) {
#if 0
		DeleteNotificationIcon();
#else
		RestoreTooltip();
#endif
		return TRUE;
	}

	return DefWindowProc(hwnd, message, wParam, lParam);
}

static const char* lpszClassName = "NOTIFY_CLASS";

static BOOL AddNotificationIcon(void)
{
	NOTIFYICONDATA nid = {0};
	TCHAR path[MAX_PATH]={0};
	BOOL r;

	hwndNotification = create_invisible_window(lpszClassName, WndProc, sc_notify_instance);
	if (!hwndNotification) {
		return FALSE;
	}

	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = hwndNotification;
	// add the icon, setting the icon, tooltip, and callback message.
	// the icon will be identified with the GUID
	nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP | NIF_GUID;
	nid.guidItem = myGUID; 
	nid.uCallbackMessage = WMAPP_NOTIFYCALLBACK;
	LoadIconMetric(sc_notify_instance, MAKEINTRESOURCEW(IDI_SMARTCARD), LIM_SMALL, &nid.hIcon);
	if (GetModuleFileName(NULL, path, ARRAYSIZE(path))) {
		const char *basename = strrchr(path, '\\');
		if (basename) {
			basename++;
			if (0 != strcmp(basename, "opensc-notify.exe")) {
				/* Allow creation of system tray icon only for
				 * "opensc-notify.exe" to avoid creation of the same icon by
				 * multiple processes. */
				delete_icon = FALSE;
				return FALSE;
			}
		}
		strlcpy(nid.szTip, path, ARRAYSIZE(nid.szTip));
	} else {
		strcpy(nid.szTip, PACKAGE_NAME);
	}

	r  = Shell_NotifyIcon(NIM_ADD, &nid);

    nid.uVersion = NOTIFYICON_VERSION_4;
    r &= Shell_NotifyIcon(NIM_SETVERSION, &nid);

	return r;
}

static BOOL DeleteNotificationIcon(void)
{
	BOOL r;
	NOTIFYICONDATA nid = {0};

	if (!delete_icon) {
		return FALSE;
	}

	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.uFlags = NIF_GUID;
	nid.guidItem = myGUID; 

	r  = Shell_NotifyIcon(NIM_DELETE, &nid);

	r &= delete_invisible_window(hwndNotification, lpszClassName,
			sc_notify_instance);

	return r;
}

static BOOL RestoreTooltip()
{
    // After the balloon is dismissed, restore the tooltip.
	NOTIFYICONDATA nid = {0};

	nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.uFlags = NIF_SHOWTIP | NIF_GUID;
	nid.guidItem = myGUID; 

    return Shell_NotifyIcon(NIM_MODIFY, &nid);
}

static void notify_shell(struct sc_context *ctx,
		const char *title, const char *text, LPCTSTR icon_path, int icon_index)
{
	NOTIFYICONDATA nid = {0};
	HICON icon = NULL;

	nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.uFlags = NIF_GUID;
    nid.guidItem = myGUID;

	if (title) {
		strlcpy(nid.szInfoTitle, title, ARRAYSIZE(nid.szInfoTitle));
	}
	if (text) {
		nid.uFlags |= NIF_INFO;
		strlcpy(nid.szInfo, text, ARRAYSIZE(nid.szInfo));
	}
	if (icon_path) {
		ExtractIconEx(icon_path, icon_index, &icon, NULL, 1);
		if (icon) {
			nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
			nid.hBalloonIcon = icon;
		}
	}

    Shell_NotifyIcon(NIM_MODIFY, &nid);

	if (icon) {
		DestroyIcon(icon);
	}
}

void sc_notify_init(void)
{
	if (!sc_notify_instance) {
		/* returns the HINSTANCE of the exe. If the code executes in a DLL,
		 * sc_notify_instance_notify should be pre-initialized */
		sc_notify_instance = GetModuleHandle(NULL);
	}
	AddNotificationIcon();
}

void sc_notify_close(void)
{
	DeleteNotificationIcon();
}

void sc_notify(const char *title, const char *text)
{
	notify_shell(NULL, title, text, NULL, 0);
}

void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id)
{
	const char *title, *text;
	LPCTSTR icon_path = NULL;
	int icon_index = 0;
	title = ui_get_str(ctx, atr, p15card, id);
	text = ui_get_str(ctx, atr, p15card, id+1);

	switch (id) {
		case NOTIFY_CARD_INSERTED:
			icon_path = TEXT("%SYSTEMROOT%\\system32\\SCardDlg.dll");
			icon_index = 3;
			break;
		case NOTIFY_CARD_REMOVED:
			icon_path = TEXT("%SYSTEMROOT%\\system32\\SCardDlg.dll");
			icon_index = 2;
			break;
		case NOTIFY_PIN_GOOD:
			icon_path = TEXT("%SYSTEMROOT%\\system32\\certmgr.dll");
			icon_index = 16;
			break;
		case NOTIFY_PIN_BAD:
			icon_path = TEXT("%SYSTEMROOT%\\system32\\certmgr.dll");
			icon_index = 11;
			break;
		default:
			break;
	}

	notify_shell(ctx, title, text, icon_path, icon_index);
}

#elif defined(ENABLE_NOTIFY) && defined(__APPLE__)

static void notify_proxy(struct sc_context *ctx,
		const char *title, const char* subtitle,
		const char *text, const char *icon, const char *sound,
		const char *group)
{
	/* terminal-notifier does not reliably activate keychain when clicked on
	 * the notification
	 * (https://github.com/julienXX/terminal-notifier/issues/196), that's why
	 * we're including NotificationProxy which has similar features */
	const char notificationproxy[] = "/Library/Security/tokend/OpenSC.tokend/Contents/Resources/Applications/NotificationProxy.app/Contents/MacOS/NotificationProxy";

	if (ctx && ctx->app_name
			&& (0 == strcmp(ctx->app_name, "opensc-pkcs11")
				|| 0 == strcmp(ctx->app_name, "onepin-opensc-pkcs11"))) {
		/* some programs don't like forking when loading our PKCS#11 module,
		 * see https://github.com/OpenSC/OpenSC/issues/1174.
		 * TODO implementing an XPC service which sends the notification should
		 * work, though. See
		 * https://github.com/OpenSC/OpenSC/issues/1304#issuecomment-376656003 */
		return;
	}

	if (child > 0) {
		int status;
		if (0 == waitpid(child, &status, WNOHANG)) {
			kill(child, SIGKILL);
			usleep(100);
			if (0 == waitpid(child, &status, WNOHANG)) {
				sc_log(ctx, "Can't kill %ld, skipping current notification", (long) child);
				return;
			}
		}
	}

	child = fork();
	switch (child) {
		case 0:
			/* child process */

			/* for some reason the user _tokend can call brew's installation of
			 * terminal-notifier, but it cannot call `/usr/bin/open` with
			 * NotificationProxy.app that we're shipping... However, while
			 * `sudo -u _tokend /usr/local/bin/terminal-notifier -title test`
			 * works in the terminal, it hangs when executed from the tokend
			 * process.  For now, we try to deliver the notification anyway
			 * making sure that we are waiting for only one forked process. */
			if (0 > execl(notificationproxy, notificationproxy,
						title ? title : "",
						subtitle ? subtitle : "",
						text ? text : "",
						icon ? icon : "",
						group ? group : "",
						sound ? sound : "",
						(char *) NULL)) {
				perror("exec failed");
				exit(0);
			}
			break;
		case -1:
			sc_log(ctx, "failed to fork for notification");
			break;
		default:
			if (ctx) {
				sc_log(ctx, "Created %ld for notification:", (long) child);
				sc_log(ctx, "%s %s %s %s %s %s %s", notificationproxy,
						title ? title : "",
						subtitle ? subtitle : "",
						text ? text : "",
						icon ? icon : "",
						group ? group : "",
						sound ? sound : "");
			}
			break;
	}
}

void sc_notify(const char *title, const char *text)
{
	notify_proxy(NULL, title, NULL, text, NULL, NULL, NULL);
}

void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id)
{
	const char *title, *text, *icon, *group;
	title = ui_get_str(ctx, atr, p15card, id);
	text = ui_get_str(ctx, atr, p15card, id+1);

	if (p15card && p15card->card && p15card->card->reader) {
		group = p15card->card->reader->name;
	} else {
		group = ctx ? ctx->app_name : NULL;
	}

	switch (id) {
		case NOTIFY_CARD_INSERTED:
			icon = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/VCard.icns";
			break;
		case NOTIFY_CARD_REMOVED:
			icon = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/EjectMediaIcon.icns";
			break;
		case NOTIFY_PIN_GOOD:
			icon = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/UnlockedIcon.icns";
			break;
		case NOTIFY_PIN_BAD:
			icon = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns";
			break;
		default:
			icon = NULL;
			break;
	}

	notify_proxy(ctx, title, NULL, text, icon, NULL, group);
}

#elif defined(ENABLE_NOTIFY) && defined(ENABLE_GIO2)

#include <gio/gio.h>

static GApplication *application = NULL;

void sc_notify_init(void)
{
	sc_notify_close();
	application = g_application_new("org.opensc.notify", G_APPLICATION_NON_UNIQUE);
	if (application) {
		g_application_register(application, NULL, NULL);
	}
}

void sc_notify_close(void)
{
	if (application) {
		g_object_unref(application);
		application = NULL;
	}
}

static void notify_gio(struct sc_context *ctx,
		const char *title, const char *text, const char *icon,
		const char *group)
{
	if (application
			&& g_application_get_is_registered(application)
			&& g_application_get_dbus_connection(application)) {
		GIcon *gicon = NULL;
		GNotification *notification = g_notification_new(title);
		if (!notification) {
			return;
		}

		if (text) {
			g_notification_set_body(notification, text);
		}
		if (icon) {
			gicon = g_themed_icon_new(icon);
			if (gicon) {
				g_notification_set_icon(notification, gicon);
			}
		}

		g_application_send_notification(application, group, notification);

		if (gicon) {
			g_object_unref(gicon);
		}
		g_object_unref(notification);
	}
}

#else

void sc_notify_init(void) {}
void sc_notify_close(void) {}
void sc_notify(const char *title, const char *text) {}
void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id) {}

#endif

#if defined(ENABLE_NOTIFY) && defined(ENABLE_GIO2)
void sc_notify(const char *title, const char *text)
{
	notify_gio(NULL, title, text, NULL, NULL);
}

void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id)
{
	const char *title, *text, *icon, *group;
	title = ui_get_str(ctx, atr, p15card, id);
	text = ui_get_str(ctx, atr, p15card, id+1);

	if (p15card && p15card->card && p15card->card->reader) {
		group = p15card->card->reader->name;
	} else {
		group = ctx ? ctx->app_name : NULL;
	}

	switch (id) {
		case NOTIFY_CARD_INSERTED:
			icon = "contact-new";
			break;
		case NOTIFY_CARD_REMOVED:
			icon = "media-eject";
			break;
		case NOTIFY_PIN_GOOD:
			icon = "changes-allow";
			break;
		case NOTIFY_PIN_BAD:
			icon = "changes-prevent";
			break;
		default:
			icon = NULL;
			break;
	}

	notify_gio(ctx, title, text, icon, group);
}

#endif
