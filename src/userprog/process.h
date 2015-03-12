#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <user/syscall.h>

/* 
    Defines Load States.
    LOAD_PENDING = load() has not been called
    LOAD_SUCCESS = load() returned true
    LOAD_FAILURE = load() return false
*/
enum load_status
{
	LOAD_PENDING,
	LOAD_SUCCESS,
	LOAD_FAILURE
};

/*
    Process Bookkeeping
     Stores the process information for a user process running in a thread
*/
struct process {
    pid_t pid;                          /* My process ID */
    tid_t parent_tid;                   /* My parent thread TID */
    bool already_waiting;               /* True: wait() already called on me, False otherwise */
    enum load_status load_state;        /* LOAD status used for signaling exec() in parent to complete */
    bool is_done;                       /* True: exit() already called on me, False otherwise */
    int exit_status;                    /* Return status for exit() call. */
    int fd;                             /* Next available FD to issue for files opened by this process */
    struct list_elem cpelem;            /* List element for child_list when a child of other processes */
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
