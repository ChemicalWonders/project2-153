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
struct process_info {
   
    //Process Identification Values
    pid_t pid;                        // My process ID
    tid_t tid;                        // My parent thread TID
    
    //Simple Values
    int fd;                           // value of file directory, checks if it can be used or not 
    int exit_stat;                    // returns if the function is going to exit or not
    
    //Function checking
    bool waiting;                     // If process is waiting, it will be true, otherwise false. 
    bool is_done;                        // if exit() is called, then i return true 

    //Data Structures
    enum load_status load_state;      // load_state is used for changing from waiting to running
    struct list_elem list_ele;       // element list
};

//Executes the process, returns the parent thread id if it exists.
tid_t process_execute (const char *file_name);

//Process will wait
int process_wait (tid_t);

//Exits the process and leaves
void process_exit (void);

//Activates the process
void process_activate (void);

#endif /* userprog/process.h */
