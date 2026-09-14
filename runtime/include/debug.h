#ifndef DEBUG_H
#define DEBUG_H

#include <stdint.h>

int debug_enabled(void);
void debug_runtime_activated(void);
void debug_log(const char *message);
void debug_log_hex(const char *prefix, uint64_t value);
void debug_log_dec(const char *prefix, uint64_t value);

#endif
