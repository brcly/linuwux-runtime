#ifndef KUSER_H
#define KUSER_H

#include <stddef.h>
#include <stdint.h>

enum kuser_profile {
    KUSER_PROFILE_MODERN = 0,
    KUSER_PROFILE_LEGACY = 1,
};

int kuser_apply_to_buffer(uint8_t *page, size_t length, enum kuser_profile profile, int avx_enabled);
int patch_kuser_shared_data_profile(enum kuser_profile profile);
int patch_kuser_shared_data(void);

#endif
