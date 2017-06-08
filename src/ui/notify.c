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

#if defined(ENABLE_NOTIFY) && (defined(__APPLE__) || defined(GDBUS))

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

#if defined(ENABLE_NOTIFY) && defined(__APPLE__)

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

#elif defined(ENABLE_NOTIFY) && defined(GDBUS)

#include <inttypes.h>
/* save the notification's id for replacement with a new one */
uint32_t message_id = 0;

static void notify_gio(struct sc_context *ctx,
		const char *title, const char *text, const char *icon,
		const char *group)
{
	char message_id_str[22];
	int pipefd[2];
	int pass_to_pipe = 1;
	snprintf(message_id_str, sizeof message_id_str, "%"PRIu32, message_id);

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

	if (0 == pipe(pipefd)) {
		pass_to_pipe = 1;
	}

	child = fork();
	switch (child) {
		case 0:
			/* child process */
			if (pass_to_pipe) {
				/* close reading end of the pipe */
				close(pipefd[0]);
				/* send stdout to the pipe */
				dup2(pipefd[1], 1);
				/* this descriptor is no longer needed */
				close(pipefd[1]);
			}

			if (0 > execl(GDBUS, GDBUS,
						"call", "--session",
						"--dest", "org.freedesktop.Notifications",
						"--object-path", "/org/freedesktop/Notifications",
						"--method", "org.freedesktop.Notifications.Notify",
						"org.opensc-project",
						message_id_str,
						icon ? icon : "",
						title ? title : "",
						text ? text : "",
						"[]", "{}", "5000",
						(char *) NULL)) {
				perror("exec failed");
				exit(1);
			}
			break;
		case -1:
			sc_log(ctx, "failed to fork for notification");
			break;
		default:
			/* parent process */

			if (ctx) {
				sc_log(ctx, "Created %ld for notification:", (long) child);
				sc_log(ctx, "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s", GDBUS,
						"call", "--session",
						"--dest", "org.freedesktop.Notifications",
						"--object-path", "/org/freedesktop/Notifications",
						"--method", "org.freedesktop.Notifications.Notify",
						"org.opensc-project",
						message_id_str,
						icon ? icon : "",
						title ? title : "",
						text ? text : "",
						"[]", "{}", "5000");
			}

			if (pass_to_pipe) {
				/* close the write end of the pipe */
				close(pipefd[1]);
				memset(message_id_str, '\0', sizeof message_id_str);
				if (0 < read(pipefd[0], message_id_str, sizeof(message_id_str))) {
					message_id_str[(sizeof message_id_str) - 1] = '\0';
					sscanf(message_id_str, "(uint32 %"SCNu32",)", &message_id);
				}
				/* close the read end of the pipe */
				close(pipefd[0]);
			}
			break;
	}
}

#elif defined(ENABLE_NOTIFY) && defined(ENABLE_GIO2)

static GtkApplication *application = NULL;

#include <gio/gio.h>

void sc_notify_init(void)
{
	sc_notify_close();
	application = g_application_new("org.opensc-project", G_APPLICATION_FLAGS_NONE);
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
	GIcon *gicon = NULL;
	GNotification *notification = g_notification_new (title);
	if (!notification) {
		return;
	}

	g_notification_set_body (notification, text);
	if (icon) {
		gicon = g_themed_icon_new (icon);
		if (gicon) {
			g_notification_set_icon (notification, gicon);
		}
	}

	g_application_send_notification(application, group, notification);

	if (gicon) {
		g_object_unref(gicon);
	}
	g_object_unref(notification);
}

#else

void sc_notify_init(void) {}
void sc_notify_close(void) {}
void sc_notify(const char *title, const char *text) {}
void sc_notify_id(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id) {}

#endif

#if defined(ENABLE_NOTIFY) && (defined(ENABLE_GIO2) || defined(GDBUS))
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
			icon = "dialog-information";
			break;
		case NOTIFY_CARD_REMOVED:
			icon = "media-removed";
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
