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
 *
 * NtQuerySystemTime -- what GetSystemTime()/GetSystemTimeAsFileTime()
 * and most Windows time queries actually resolve to -- calls
 * clock_gettime() directly in the client process; it does not ask
 * wineserver (see dlls/ntdll/unix/sync.c upstream). That path was
 * already covered by the process-local interposition below before
 * this file gained the prefix-shared state. What the shared state
 * adds is narrower: wineserver's own gettimeofday() (its internal
 * bookkeeping/timeouts, and whatever else still goes through
 * gettimeofday rather than NtQuerySystemTime) wouldn't otherwise see
 * a handshake armed inside the game's own process. Real, just not the
 * primary path. linuwux_faketime_prefix_init() below opens a small
 * mmap'd file inside the Wine prefix itself that both processes share
 * for this.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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

/* Process-local faketime, used by clock_gettime() (which stays purely
 * per-process -- see the file comment above) and as the game's own
 * fallback when the prefix-shared file below isn't available. */
static _Atomic int64_t g_faketime_offset;
static _Atomic int g_faketime_active;

/*
 * Prefix-shared faketime.
 *
 * A dotfile directly under $WINEPREFIX (no hashing needed -- the
 * prefix directory is already exactly the right scope) holds the
 * published offset. layout_tag guards against a stale file left by a
 * different build; a fresh ftruncate()'d file already reads back as
 * all zero, so any reader racing the very first initialization just
 * sees "not active", never garbage. active is stored last on every
 * write (after offset), so a reader that observes active==1 via an
 * acquire load is guaranteed to see the matching offset too.
 */
struct linuwux_faketime_prefix_state {
    _Atomic uint32_t layout_tag;
    _Atomic uint32_t active;
    _Atomic int64_t offset;
};

#define LINUWUX_FAKETIME_PREFIX_TAG 0x4c465431u /* "LFT1" */

static struct linuwux_faketime_prefix_state *g_prefix_state; /* NULL if unavailable */

static struct linuwux_faketime_prefix_state *linuwux_faketime_open_prefix_state(void)
{
    const char *prefix;
    char path[PATH_MAX];
    int fd;
    struct stat st;
    void *mapping;
    struct linuwux_faketime_prefix_state *state;

    prefix = getenv("WINEPREFIX");
    if (!prefix || !*prefix)
        return NULL;

    if (snprintf(path, sizeof(path), "%s/.linuwux-faketime", prefix) >= (int)sizeof(path))
        return NULL;

    fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0)
        return NULL;

    if (flock(fd, LOCK_EX) != 0)
    {
        close(fd);
        return NULL;
    }

    if (fstat(fd, &st) != 0)
    {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }

    if (st.st_size != (off_t)sizeof(*state) &&
        ftruncate(fd, (off_t)sizeof(*state)) != 0)
    {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }

    mapping = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED)
    {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }

    state = (struct linuwux_faketime_prefix_state *)mapping;

    if (atomic_load_explicit(&state->layout_tag, memory_order_relaxed) != LINUWUX_FAKETIME_PREFIX_TAG)
    {
        atomic_store_explicit(&state->active, 0, memory_order_relaxed);
        atomic_store_explicit(&state->offset, 0, memory_order_relaxed);
        atomic_store_explicit(&state->layout_tag, LINUWUX_FAKETIME_PREFIX_TAG, memory_order_release);
    }

    /* The fd isn't needed once mapped; the mapping outlives it. */
    flock(fd, LOCK_UN);
    close(fd);

    return state;
}

void linuwux_faketime_prefix_init(void)
{
    g_prefix_state = linuwux_faketime_open_prefix_state();

    if (g_prefix_state && linuwux_is_wineserver())
    {
        /* wineserver starting is this prefix's signal that a new Wine
         * session has begun -- without this, a faketime handshake
         * armed during an earlier session (a previous launch that has
         * since quit) would otherwise keep applying to every later
         * one until the file happened to get deleted. wineserver is
         * up well before the game can reach its own handshake, so
         * this can't race a legitimate arm from the new session.
         * active=0 first (release) so a concurrent reader stops
         * trusting the stale offset as soon as this is visible. */
        atomic_store_explicit(&g_prefix_state->active, 0, memory_order_release);
        atomic_store_explicit(&g_prefix_state->offset, 0, memory_order_relaxed);
    }

    linuwux_log("faketime: prefix-shared state %s (%s)\n",
                g_prefix_state ? "ready" : "unavailable",
                linuwux_is_wineserver() ? "wineserver" : "game");
}

/* Whatever offset is currently published for this prefix -- the
 * shared one if we have it and it's active, otherwise our own local
 * one. Used both to compute a new handshake relative to already-faked
 * time and by gettimeofday() below. */
static int linuwux_faketime_current_offset(int64_t *offset)
{
    if (g_prefix_state && atomic_load_explicit(&g_prefix_state->active, memory_order_acquire))
    {
        *offset = atomic_load_explicit(&g_prefix_state->offset, memory_order_acquire);
        return 1;
    }
    if (atomic_load(&g_faketime_active))
    {
        *offset = atomic_load(&g_faketime_offset);
        return 1;
    }
    return 0;
}

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
    int64_t offset;

    if (!real_gettimeofday)
        real_gettimeofday = (gettimeofday_fn)dlsym(RTLD_NEXT, "gettimeofday");

    /* wineserver is included here (unlike clock_gettime above) because
     * it's the process a lot of Windows time queries actually reach --
     * see the file comment at the top. */
    if (!linuwux_is_game_process() && !linuwux_is_wineserver())
        return real_gettimeofday(tv, tz);

    ret = real_gettimeofday(tv, tz);

    if (ret == 0 && linuwux_faketime_current_offset(&offset))
    {
        int64_t ticks = linuwux_unix_to_ticks(tv->tv_sec, tv->tv_usec * 1000) - offset;
        time_t sec;
        long nsec;
        linuwux_ticks_to_unix(ticks, &sec, &nsec);
        tv->tv_sec = sec;
        tv->tv_usec = nsec / 1000;
    }

    return ret;
}

/* offset = ((effective >> 32) - requested) << 32, where "effective" is
 * real time adjusted by whatever faketime offset is already published
 * for this prefix (not raw real time) -- so a second handshake lands
 * relative to the time the game is already seeing, rather than
 * stacking a fresh offset on top of the first. Uses real_clock_gettime
 * to avoid recursion. */
void linuwux_set_faketime(long long requested)
{
    struct timespec ts;
    int64_t now_ticks, effective_ticks, already_offset, high32, offset;

    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");

    if (real_clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        linuwux_log("faketime: clock_gettime(CLOCK_REALTIME) failed: %s -- skipping\n", strerror(errno));
        return;
    }

    now_ticks = linuwux_unix_to_ticks(ts.tv_sec, ts.tv_nsec);
    effective_ticks = now_ticks;
    if (linuwux_faketime_current_offset(&already_offset))
        effective_ticks -= already_offset;

    high32 = effective_ticks >> 32;
    offset = (high32 - requested) << 32;

    atomic_store(&g_faketime_offset, offset);
    atomic_store(&g_faketime_active, 1);

    if (g_prefix_state)
    {
        /* Offset before active: see the struct comment above. */
        atomic_store_explicit(&g_prefix_state->offset, offset, memory_order_release);
        atomic_store_explicit(&g_prefix_state->active, 1, memory_order_release);
    }

    linuwux_log("faketime: requested=%llx effective_ticks_hi32=%llx -> offset=%llx%s\n",
                requested, (unsigned long long)high32, (unsigned long long)offset,
                g_prefix_state ? " (published)" : "");
}
