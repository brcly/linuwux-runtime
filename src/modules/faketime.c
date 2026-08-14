/*
 * Copyright (C) 2026 brcly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * linuwux -- faketime: client-side clock_gettime()/gettimeofday()
 * interposition (REALTIME clocks only).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "linuwux.h"
#include "faketime.h"

#define LINUWUX_TICKS_PER_SEC      10000000LL
#define LINUWUX_TICKS_1601_TO_1970 116444736000000000LL

/* FILETIME-style: 100ns ticks since 1601-01-01. */
static int64_t linuwux_unix_to_ticks(time_t sec, long nsec)
{
    return (int64_t)sec * LINUWUX_TICKS_PER_SEC + nsec / 100 + LINUWUX_TICKS_1601_TO_1970;
}

static void linuwux_ticks_to_unix(int64_t ticks, time_t *sec, long *nsec)
{
    int64_t unix_ticks = ticks - LINUWUX_TICKS_1601_TO_1970;
    if (unix_ticks < 0)
        unix_ticks = 0;
    *sec = (time_t)(unix_ticks / LINUWUX_TICKS_PER_SEC);
    *nsec = (long)(unix_ticks % LINUWUX_TICKS_PER_SEC) * 100;
}

static _Atomic int64_t g_faketime_offset;
static _Atomic int g_faketime_active;

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static clock_gettime_fn real_clock_gettime;

__attribute__((visibility("default")))
int clock_gettime(clockid_t id, struct timespec *ts)
{
    int ret;

    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");

    if (!linuwux_is_game_process())
        return real_clock_gettime(id, ts);

    ret = real_clock_gettime(id, ts);

    if (ret == 0 && atomic_load(&g_faketime_active) &&
        (id == CLOCK_REALTIME
#ifdef CLOCK_REALTIME_COARSE
         || id == CLOCK_REALTIME_COARSE
#endif
        ))
    {
        int64_t offset = atomic_load(&g_faketime_offset);
        int64_t ticks = linuwux_unix_to_ticks(ts->tv_sec, ts->tv_nsec) - offset;
        linuwux_ticks_to_unix(ticks, &ts->tv_sec, &ts->tv_nsec);
    }

    return ret;
}

typedef int (*gettimeofday_fn)(struct timeval *, void *);
static gettimeofday_fn real_gettimeofday;

__attribute__((visibility("default")))
int gettimeofday(struct timeval *tv, void *tz)
{
    int ret;

    if (!real_gettimeofday)
        real_gettimeofday = (gettimeofday_fn)dlsym(RTLD_NEXT, "gettimeofday");

    if (!linuwux_is_game_process())
        return real_gettimeofday(tv, tz);

    ret = real_gettimeofday(tv, tz);

    if (ret == 0 && atomic_load(&g_faketime_active))
    {
        int64_t offset = atomic_load(&g_faketime_offset);
        int64_t ticks = linuwux_unix_to_ticks(tv->tv_sec, tv->tv_usec * 1000) - offset;
        time_t sec;
        long nsec;
        linuwux_ticks_to_unix(ticks, &sec, &nsec);
        tv->tv_sec = sec;
        tv->tv_usec = nsec / 1000;
    }

    return ret;
}

/* offset = ((now >> 32) - requested) << 32; uses real_clock_gettime to avoid recursion. */
void linuwux_set_faketime(long long requested)
{
    struct timespec ts;
    int64_t now_ticks, high32, offset;

    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");

    if (real_clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        linuwux_log("faketime: clock_gettime(CLOCK_REALTIME) failed: %s -- skipping\n", strerror(errno));
        return;
    }

    now_ticks = linuwux_unix_to_ticks(ts.tv_sec, ts.tv_nsec);
    high32 = now_ticks >> 32;
    offset = (high32 - requested) << 32;

    atomic_store(&g_faketime_offset, offset);
    atomic_store(&g_faketime_active, 1);
    linuwux_log("faketime: requested=%llx now_ticks_hi32=%llx -> offset=%llx\n",
                requested, (unsigned long long)high32, (unsigned long long)offset);
}
