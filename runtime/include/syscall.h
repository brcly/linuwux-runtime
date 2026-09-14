#ifndef SYSCALL_H
#define SYSCALL_H
#include <signal.h>

void syscallhook(int sig, siginfo_t *info, void *context);

#endif
