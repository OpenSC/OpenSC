/*
 * invisible_window.h: Create invisible Window
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

#include <windows.h>

HWND create_invisible_window(LPCTSTR lpszClassName,
		LRESULT (CALLBACK* WndProc)(HWND, UINT, WPARAM, LPARAM),
		HINSTANCE hInstance)
{
	HWND hWnd = NULL;
	WNDCLASSEX wx = {0};

	//Register Window class
	wx.cbSize = sizeof(WNDCLASSEX);
	wx.lpfnWndProc = WndProc;
	wx.hInstance = hInstance;
	wx.lpszClassName = lpszClassName;
	if (RegisterClassEx(&wx)) {
		/* create window */
		hWnd = CreateWindowEx(0, lpszClassName, lpszClassName, 0, 0, 0, 0, 0,
				HWND_MESSAGE, NULL, NULL, NULL );
	}

	return hWnd;
}

static BOOL delete_invisible_window(HWND hWnd, LPCTSTR lpszClassName,
	   	HINSTANCE hInstance)
{
	BOOL r;
   	r  = DestroyWindow(hWnd);
	r &= UnregisterClass(lpszClassName, hInstance);
	
	return r;
}
