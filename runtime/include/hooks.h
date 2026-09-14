#ifndef HOOKS_H
#define HOOKS_H

#include <signal.h>

void forward_signal(int sig, siginfo_t *info, void *context);

#endif
