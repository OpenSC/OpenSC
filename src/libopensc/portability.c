/*
 * portability.c: Miscellaneous stuff needed for porting to other platforms
 *
 * Copyright (C) 2003, Olaf Kirch <okir@lst.de>
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

#include "internal.h"
#include <assert.h>
#include <stdlib.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if defined(HAVE_PTHREAD)
#include <pthread.h>

sc_mutex_t *
sc_mutex_new(void)
{
	pthread_mutex_t *mutex;

	mutex = (pthread_mutex_t *) malloc(sizeof(*mutex));
	assert(mutex);
	pthread_mutex_init(mutex, NULL);
	return (sc_mutex_t *) mutex;
}

void
sc_mutex_lock(sc_mutex_t *p)
{
	pthread_mutex_lock((pthread_mutex_t *) p);
}

void
sc_mutex_unlock(sc_mutex_t *p)
{
	pthread_mutex_unlock((pthread_mutex_t *) p);
}

void
sc_mutex_free(sc_mutex_t *p)
{
	pthread_mutex_destroy((pthread_mutex_t *) p);
	free(p);
}
#elif defined(_WIN32)

sc_mutex_t *
sc_mutex_new(void)
{
	CRITICAL_SECTION *mutex;

	mutex = (CRITICAL_SECTION *) malloc(sizeof(*mutex));
	assert(mutex);
	InitializeCriticalSection(mutex);
	return (sc_mutex_t *) mutex;
}

void
sc_mutex_lock(sc_mutex_t *p)
{
	EnterCriticalSection((CRITICAL_SECTION *) p);
}

void
sc_mutex_unlock(sc_mutex_t *p)
{
	LeaveCriticalSection((CRITICAL_SECTION *) p);
}

void
sc_mutex_free(sc_mutex_t *p)
{
	DeleteCriticalSection((CRITICAL_SECTION *) p);
	free(p);
}
#else
sc_mutex_t *
sc_mutex_new(void)
{
	return (sc_mutex_t *) NULL;
}

void
sc_mutex_lock(sc_mutex_t *p)
{
	/* NOP */
}

void
sc_mutex_unlock(sc_mutex_t *p)
{
	/* NOP */
}

void
sc_mutex_free(sc_mutex_t *p)
{
	/* NOP */
}
#endif

#ifndef _WIN32
sc_timestamp_t sc_current_time(void)
{
	struct timeval tv;
	struct timezone tz;
	sc_timestamp_t curr;

	if (gettimeofday(&tv, &tz) != 0)
		return 0;

	curr = tv.tv_sec;
	curr *= 1000;
	curr += tv.tv_usec / 1000;

	return curr;
}
#else
sc_timestamp_t sc_current_time(void)
{
	struct _timeb time_buf;
	sc_timestamp_t curr;

	_ftime(&time_buf);

	curr = time_buf.time;
	curr *= 1000;
	curr += time_buf.millitm;

	return curr;
}
#endif
