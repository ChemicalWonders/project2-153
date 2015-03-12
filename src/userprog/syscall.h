#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);
void process_cleanup (struct thread* t);

#endif /* userprog/syscall.h */
