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

void stop_daemon()
{
#ifdef PCSCLITE_GOOD
	sc_cancel(ctx);
#endif
	run_daemon = 0;
}

void notify_daemon()
{
	int r;
	const unsigned int event_mask = SC_EVENT_CARD_EVENTS;
	unsigned int event;
	struct sc_reader *event_reader = NULL;
	size_t error_count = 0;
	/* timeout adjusted to the maximum response time for WM_CLOSE in case
	 * canceling doesn't work */
	const int timeout = 20000;
	struct sc_atr old_atr;
	void *reader_states = NULL;

	r = sc_establish_context(&ctx, "opensc-notify");
	if (r < 0 || !ctx) {
		fprintf(stderr, "Failed to create initial context: %s", sc_strerror(r));
		return;
	}

	while (run_daemon && error_count < 1000) {
		r = sc_wait_for_event(ctx, event_mask,
				&event_reader, &event, timeout, &reader_states);
		if (r < 0) {
			if (r == SC_ERROR_NO_READERS_FOUND) {
				/* No readers available, PnP notification not supported */
				Sleep(200);
			} else {
				error_count++;
			}
			continue;
		}

		error_count = 0;

		if (event & SC_EVENT_CARD_REMOVED) {
			sc_notify_id(ctx, &old_atr, NULL, NOTIFY_CARD_REMOVED);
		}
		if (event & SC_EVENT_CARD_INSERTED) {
			if (event_reader) {
				/* FIXME `pcsc_wait_for_event` has all the information that's
				 * requested again with `pcsc_detect_card_presence`, but it
				 * doesn't use the ATR, for example, to refresh the reader's
				 * attributes. To get the ATR we need to call
				 * sc_detect_card_presence. Eventually this should be fixed. */
				sc_detect_card_presence(event_reader);
				memcpy(old_atr.value, event_reader->atr.value,
						event_reader->atr.len);
				old_atr.len = event_reader->atr.len;
			} else {
				old_atr.len = 0;
			}
			sc_notify_id(ctx, old_atr.len ? &old_atr : NULL, NULL,
					NOTIFY_CARD_INSERTED);
		}
	}

	if (ctx) {
		if (error_count >= 1000) {
			sc_log(ctx, "Too many errors; aborting.");
		}
		/* free `reader_states` */
		sc_wait_for_event(ctx, 0, NULL, NULL, 0, &reader_states);
		reader_states = NULL;
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
		stop_daemon();
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

#ifdef HAVE_SIGACTION
#include <signal.h>

void sig_handler(int sig) {
	stop_daemon();
}

void set_sa_handler(void)
{
	struct sigaction new_sig, old_sig;

	/* Register signal handlers */
	new_sig.sa_handler = sig_handler;
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_flags = SA_RESTART;
	if ((sigaction(SIGINT, &new_sig, &old_sig) < 0)
			|| (sigaction(SIGTERM, &new_sig, &old_sig) < 0)) {
		fprintf(stderr, "Failed to create signal handler: %s", strerror(errno));
	}
}

#else

void set_sa_handler(void)
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
		set_sa_handler();
		run_daemon = 1;
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
