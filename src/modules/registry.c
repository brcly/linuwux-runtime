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
 * linuwux -- HwProfileGuid, written via the real NT registry API.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "linuwux.h"
#include "registry.h"

/*
 * Resolve a symbol from ntdll.so (not visible via RTLD_DEFAULT).
 * Path comes from /proc/self/maps + RTLD_NOLOAD.
 * May run under SIGSEGV (arm -> hwprofile); fopen/dlopen are not AS-safe.
 * Late callers do not wait on a stuck resolver — return NULL instead.
 */
enum { LINUWUX_NTDLL_NOT_STARTED = 0, LINUWUX_NTDLL_IN_PROGRESS = 1, LINUWUX_NTDLL_DONE = 2 };

static void *linuwux_find_ntdll_symbol(const char *name)
{
    static _Atomic(void *) ntdll_handle;
    static _Atomic int state;
    int expected_state = LINUWUX_NTDLL_NOT_STARTED;
    void *handle;

    if (atomic_compare_exchange_strong(&state, &expected_state, LINUWUX_NTDLL_IN_PROGRESS))
    {
        FILE *f;
        char line[4096], path[4096];

        handle = NULL;
        path[0] = '\0';
        f = fopen("/proc/self/maps", "r");
        if (f)
        {
            while (fgets(line, sizeof(line), f))
            {
                size_t len = strlen(line);
                const char *field;
                int i;

                if (len && line[len - 1] == '\n')
                    line[--len] = '\0';

                /* Pathname is field 6; may contain spaces. */
                field = line;
                for (i = 0; i < 5 && field; i++)
                {
                    field = strchr(field, ' ');
                    if (field)
                        while (*field == ' ')
                            field++;
                }
                if (!field || !*field)
                    continue;

                len = strlen(field);
                if (len > 9 && strcmp(field + len - 9, "/ntdll.so") == 0)
                {
                    snprintf(path, sizeof(path), "%s", field);
                    break;
                }
            }
            fclose(f);
        }
        if (path[0])
        {
            handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            linuwux_log("linuwux_find_ntdll_symbol: ntdll.so at %s -> handle=%p\n", path, handle);
        }
        else
            linuwux_log("linuwux_find_ntdll_symbol: could not find ntdll.so in /proc/self/maps\n");

        atomic_store_explicit(&ntdll_handle, handle, memory_order_release);
        atomic_store_explicit(&state, LINUWUX_NTDLL_DONE, memory_order_release);
    }

    handle = atomic_load_explicit(&ntdll_handle, memory_order_acquire);
    return handle ? dlsym(handle, name) : NULL;
}

/* --- HwProfileGuid via NT registry API --- */

struct linuwux_unicode_string
{
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
};

struct linuwux_object_attributes
{
    uint32_t Length;
    void *RootDirectory;
    struct linuwux_unicode_string *ObjectName;
    uint32_t Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
};

#define LINUWUX_OBJ_CASE_INSENSITIVE 0x00000040
#define LINUWUX_KEY_ALL_ACCESS       0x001F003F
#define LINUWUX_REG_SZ               1

typedef int32_t (*nt_create_key_fn)(void **key, uint32_t access, const struct linuwux_object_attributes *attr,
                                     uint32_t index, const struct linuwux_unicode_string *class,
                                     uint32_t options, uint32_t *disposition);
typedef int32_t (*nt_set_value_key_fn)(void *key, const struct linuwux_unicode_string *name, uint32_t index,
                                        uint32_t type, const void *data, uint32_t count);
typedef int32_t (*nt_close_fn)(void *handle);

static void linuwux_ascii_to_utf16(const char *src, uint16_t *dst, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        dst[i] = (uint16_t)(unsigned char)src[i];
}

void linuwux_set_hwprofile_guid(void)
{
    static _Atomic int done;
    int expected_done = 0;
    nt_create_key_fn nt_create_key;
    nt_set_value_key_fn nt_set_value_key;
    nt_close_fn nt_close;
    struct linuwux_unicode_string value_name;
    struct linuwux_object_attributes attr;
    void *cur, *next;
    uint16_t value_name_buf[16];
    uint16_t data_buf[48];
    size_t i;
    static const char *const path_components[] = {
        "\\Registry", "Machine", "System", "CurrentControlSet",
        "Control", "IDConfigDB", "Hardware Profiles", "0001"
    };
    static const char value_name_str[] = "HwProfileGuid";
    static const char data_str[] = "{12345678-1234-1234-1234-123456789012}";

    _Static_assert(sizeof(value_name_str) <= sizeof(value_name_buf) / sizeof(value_name_buf[0]),
                   "value_name_buf too small for value_name_str");
    _Static_assert(sizeof(data_str) <= sizeof(data_buf) / sizeof(data_buf[0]),
                   "data_buf too small for data_str");

    if (!atomic_compare_exchange_strong(&done, &expected_done, 1))
        return;

    nt_create_key = (nt_create_key_fn)linuwux_find_ntdll_symbol("NtCreateKey");
    nt_set_value_key = (nt_set_value_key_fn)linuwux_find_ntdll_symbol("NtSetValueKey");
    nt_close = (nt_close_fn)linuwux_find_ntdll_symbol("NtClose");
    if (!nt_create_key || !nt_set_value_key || !nt_close)
    {
        linuwux_log("hwprofile_guid: could not resolve NtCreateKey/NtSetValueKey/NtClose -- skipping\n");
        return;
    }

    /* NtCreateKey only creates the last component — walk path level by level. */
    cur = NULL;
    for (i = 0; i < sizeof(path_components) / sizeof(path_components[0]); i++)
    {
        const char *comp = path_components[i];
        size_t comp_len = strlen(comp);
        uint16_t comp_buf[32];
        struct linuwux_unicode_string comp_name;

        if (comp_len + 1 > sizeof(comp_buf) / sizeof(comp_buf[0]))
        {
            linuwux_log("hwprofile_guid: path component \"%s\" too long for comp_buf -- skipping\n", comp);
            if (cur)
                nt_close(cur);
            return;
        }
        linuwux_ascii_to_utf16(comp, comp_buf, comp_len + 1);
        comp_name.Length = (uint16_t)(comp_len * sizeof(uint16_t));
        comp_name.MaximumLength = (uint16_t)((comp_len + 1) * sizeof(uint16_t));
        comp_name.Buffer = comp_buf;

        attr.Length = sizeof(attr);
        attr.RootDirectory = cur;
        attr.ObjectName = &comp_name;
        attr.Attributes = LINUWUX_OBJ_CASE_INSENSITIVE;
        attr.SecurityDescriptor = NULL;
        attr.SecurityQualityOfService = NULL;

        next = NULL;
        if (nt_create_key(&next, LINUWUX_KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL) < 0 || !next)
        {
            linuwux_log("hwprofile_guid: NtCreateKey(\"%s\") failed -- skipping\n", comp);
            if (cur)
                nt_close(cur);
            return;
        }
        if (cur)
            nt_close(cur);
        cur = next;
    }

    linuwux_ascii_to_utf16(value_name_str, value_name_buf, sizeof(value_name_str));
    value_name.Length = (uint16_t)((sizeof(value_name_str) - 1) * sizeof(uint16_t));
    value_name.MaximumLength = (uint16_t)(sizeof(value_name_str) * sizeof(uint16_t));
    value_name.Buffer = value_name_buf;

    linuwux_ascii_to_utf16(data_str, data_buf, sizeof(data_str));

    if (nt_set_value_key(cur, &value_name, 0, LINUWUX_REG_SZ, data_buf,
                          (uint32_t)(sizeof(data_str) * sizeof(uint16_t))) < 0)
        linuwux_log("hwprofile_guid: NtSetValueKey failed\n");
    else
        linuwux_log("hwprofile_guid: HwProfileGuid registry value set\n");

    nt_close(cur);
}
