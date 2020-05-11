/*
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libopensc/log.h"
#include "ui/notify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_daemon = 0;
static struct sc_context *ctx = NULL;

#ifndef _WIN32
#include <time.h>

void Sleep(unsigned int Milliseconds)
{
	struct timespec req, rem;

	if (Milliseconds > 999) {
		req.tv_sec  = Milliseconds / 1000;                            /* Must be Non-Negative */
		req.tv_nsec = (Milliseconds - (req.tv_sec * 1000)) * 1000000; /* Must be in range of 0 to 999999999 */
	} else {
		req.tv_sec  = 0;                        /* Must be Non-Negative */
		req.tv_nsec = Milliseconds * 1000000;   /* Must be in range of 0 to 999999999 */
	}

	nanosleep(&req , &rem);
}
#endif

void notify_daemon()
{
	int r;
	const unsigned int event_mask = SC_EVENT_CARD_EVENTS|SC_EVENT_READER_EVENTS;
	unsigned int event;
	struct sc_reader *event_reader = NULL;
	void *reader_states = NULL;
#ifndef __APPLE__
	/* timeout adjusted to the maximum response time for WM_CLOSE in case
	 * canceling doesn't work */
	const int timeout = 20000;
#else
	/* lower timeout, because Apple doesn't support hotplug events */
	const int timeout = 2000;
#endif

	r = sc_establish_context(&ctx, "opensc-notify");
	if (r < 0 || !ctx) {
		fprintf(stderr, "Failed to create initial context: %s", sc_strerror(r));
		return;
	}

	while (run_daemon) {

		r = sc_wait_for_event(ctx, event_mask,
				&event_reader, &event, timeout, &reader_states);
		if (r < 0) {
			if (r == SC_ERROR_NO_READERS_FOUND) {
				Sleep(timeout);
				continue;
			}
		}

		if (event_reader) {
			if (event & SC_EVENT_CARD_REMOVED
					|| (event & SC_EVENT_READER_DETACHED
						&& event_reader->flags & SC_READER_CARD_PRESENT)) {
				/* sc_notify_id uses only the reader's name for displaying on
				 * removal, so use a dummy card here to get that information
				 * into the notification */
				struct sc_pkcs15_card p15card;
				sc_card_t card;
				memset(&card, 0, sizeof card);
				card.reader = event_reader;
				memset(&p15card, 0, sizeof p15card);
				p15card.card = &card;
				sc_notify_id(ctx, &event_reader->atr, &p15card, NOTIFY_CARD_REMOVED);
			} else if (event & SC_EVENT_CARD_INSERTED
					|| (event & SC_EVENT_READER_ATTACHED
						&& event_reader->flags & SC_READER_CARD_PRESENT)) {
				/* sc_notify_id prevers the reader's name for displaying on
				 * insertion, so use a dummy card here to get that information
				 * into the notification */
				struct sc_pkcs15_card p15card;
				sc_card_t card;
				memset(&card, 0, sizeof card);
				card.reader = event_reader;
				memset(&p15card, 0, sizeof p15card);
				p15card.card = &card;
				sc_notify_id(ctx, &event_reader->atr, &p15card, NOTIFY_CARD_INSERTED);
			}
		}
	}

	if (ctx) {
		/* free `reader_states` */
		sc_wait_for_event(ctx, 0, NULL, NULL, 0, &reader_states);
		sc_release_context(ctx);
		ctx = NULL;
	}
}

#ifdef _WIN32
#include "ui/invisible_window.h"
#include <shellapi.h>

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_CLOSE || message == WM_QUIT) {
		run_daemon = 0;
		sc_cancel(ctx);
		return TRUE;
	}

	return DefWindowProc(hwnd, message, wParam, lParam);
}

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter)
{
	notify_daemon();
	return 0;
}

/* This application shall be executable without a console.  Therefor we're
 * creating a windows application that requires `WinMain()` rather than
 * `main()` as entry point. As benefit, we can properly handle `WM_CLOSE`. */
int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE prevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	LPCTSTR lpszClassName = "OPENSC_NOTIFY_CLASS";
	HWND hwnd = create_invisible_window(lpszClassName, WndProc, hInstance);

	sc_notify_init();
	run_daemon = 1;
	HANDLE hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);

	MSG msg;
	BOOL bRet = FALSE;
	while((bRet = GetMessage( &msg, NULL, 0, 0 )) != 0) {
		if (bRet == -1) {
			// handle the error and possibly exit
		} else {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		if (msg.message == WM_COMMAND && LOWORD(msg.wParam) == WMAPP_EXIT) {
			break;
		}
	}

	CloseHandle(hThread);
	sc_notify_close();

	delete_invisible_window(hwnd, lpszClassName, hInstance);

	return 0;
}

#else

#if defined(HAVE_SIGACTION) && defined(HAVE_PTHREAD)
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

static int cancellation_fd[] = {-1, -1};

void sig_handler(int sig) {
	run_daemon = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	(void)write(cancellation_fd[1], &sig, sizeof sig);
#pragma GCC diagnostic pop
}

static void *cancellation_proc(void *arg)
{
	(void)arg;
	while (run_daemon) {
		int sig;
		if (sizeof sig == read(cancellation_fd[0], &sig, sizeof sig)) {
			break;
		}
	}
	sc_cancel(ctx);
	return NULL;
}

void setup_cancellation(void)
{
	pthread_t cancellation_thread;
	struct sigaction new_sig, old_sig;
	new_sig.sa_handler = sig_handler;
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_flags = SA_RESTART;

	if (pipe(cancellation_fd) != 0
			|| (errno = pthread_create(&cancellation_thread, NULL, cancellation_proc, NULL)) != 0
			|| sigaction(SIGINT, &new_sig, &old_sig) != 0
			|| sigaction(SIGTERM, &new_sig, &old_sig) != 0) {
		fprintf(stderr, "Failed to setup cancellation: %s", strerror(errno));
	}
}

#else

void setup_cancellation(void)
{
}

#endif

#include "opensc-notify-cmdline.h"

int
main (int argc, char **argv)
{
	struct gengetopt_args_info cmdline;
	memset(&cmdline, 0, sizeof cmdline);

	sc_notify_init();

	if (cmdline_parser(argc, argv, &cmdline) != 0)
		goto err;

	if (cmdline.customized_mode_counter) {
		sc_notify(cmdline.title_arg, cmdline.message_arg);
	}

	if (cmdline.standard_mode_counter) {
		if (cmdline.notify_card_inserted_flag) {
			sc_notify_id(NULL, NULL, NULL, NOTIFY_CARD_INSERTED);
		}
		if (cmdline.notify_card_removed_flag) {
			sc_notify_id(NULL, NULL, NULL, NOTIFY_CARD_REMOVED);
		}
		if (cmdline.notify_pin_good_flag) {
			sc_notify_id(NULL, NULL, NULL, NOTIFY_PIN_GOOD);
		}
		if (cmdline.notify_pin_bad_flag) {
			sc_notify_id(NULL, NULL, NULL, NOTIFY_PIN_BAD);
		}
	}

	if ((!cmdline.customized_mode_counter && !cmdline.standard_mode_counter)
			|| cmdline.daemon_mode_counter) {
		run_daemon = 1;
		setup_cancellation();
		notify_daemon();
	} else {
		/* give the notification process some time to spawn */
		Sleep(100);
	}

err:
	sc_notify_close();
	cmdline_parser_free (&cmdline);

	return 0;
}
#endif
