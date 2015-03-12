#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/malloc.h"

void halt (void);
void exit (int status);
int wait (pid_t pid);
pid_t exec (const char* cmd_line);

//Filesystem calls
bool create (const char* file, unsigned initial_size);
bool remove (const char* file);
int open (const char* file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned length);
int write (int fd, const void* buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

//Filesystem bookkeeeping as recommended by:
//http://courses.cs.vt.edu/~cs3204/fall2009/pintos-vt-local/Project2Session.pdf

//One global lock for filesystem calls as per slides recommendation
//(See consulted sources in DESIGNDOC)
struct lock file_lock;


// Info for file in threads file_list
struct file_info { 
    int fd;                     /* This files fd */ 
    struct file* file;          /* This files file pointer */
    struct list_elem felem;     /* THIS files element in file_list for a thread */
};

//File helper functions

// Build the file_info struct and add it to a process
int process_file (const char* file); 

// Get the file_info by fd or NULL if not valid
struct file_info* get_file (int fd);

// Close the file by fd. This wraps around file_close but also frees resources from file_info and file_list
void close_file (int fd);

// Wraps around close_file to free all files in a process file_list
void close_all_files (struct thread* t);

static void syscall_handler (struct intr_frame *);

/* Other helper functions */

// Validate and return a function argument from the stack
int get_arg(struct intr_frame* f, int i);

// Validate and return mutiple arguments from the stack
void fill_args(struct intr_frame *f, int* args, int numArgs);

// Validate an address and exit(-1) if invalid or unmapped
void test_bad_address(const void* addr);

// Validate and return kernel mapping of user address
void* kptr (const void* addr);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
    // Validate call number
    test_bad_address(f->esp);

    //Arguments passed to syscall, can only have 3 at most
    int funcArgs[3]; 
    int* syscall_id = (int*)f->esp;
    switch (*syscall_id) {
        case SYS_EXIT:
        {
            fill_args(f, &funcArgs[0], 1); 
            exit(funcArgs[0]);
            break;
        }
        case SYS_WAIT:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = wait(funcArgs[0]);
            break;
        }
        case SYS_HALT:
        {
            halt();
            break;
        }
        case SYS_WRITE:
        {
            fill_args(f, &funcArgs[0], 3);
            void* kp = kptr((const void*)funcArgs[1]);
            f->eax = write(funcArgs[0], (const char*)kp, (unsigned)funcArgs[2]);
            break;
        }
        case SYS_READ:
        {
            fill_args(f, &funcArgs[0], 3);
            void* kp = kptr((const void*)funcArgs[1]);
            f->eax = read(funcArgs[0], kp, (unsigned)funcArgs[2]);
            break;
        }
        case SYS_EXEC:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = exec((const char*)kp);
            break;
        }
        case SYS_CREATE:
        {
            fill_args(f, &funcArgs[0], 2);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = create((const char*)kp, (unsigned)funcArgs[1]);
            break;
        }
        case SYS_REMOVE:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = remove((const char*)kp);
            break;
        }
        case SYS_OPEN:
        {
            fill_args(f, &funcArgs[0], 1);
            void* kp = kptr((const void*)funcArgs[0]);
            f->eax = open((const char*)kp);
            break;
        }
        case SYS_FILESIZE:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = filesize(funcArgs[0]);
            break;
        }
        case SYS_SEEK:
        {
            fill_args(f, &funcArgs[0], 2);
            seek(funcArgs[0], (unsigned)funcArgs[1]);
            break;
        }
        case SYS_TELL:
        {
            fill_args(f, &funcArgs[0], 1);
            f->eax = tell(funcArgs[0]);
        }
        default:
            break; 
    }
}

void halt (void)
{
    shutdown_power_off();
}

void exit (int status)
{
    struct thread* current = thread_current();

    //Set return status and flag parent
    //This is only needed if it's a child process, as in it has a parent.
    if (get_thread(current->process->parent_tid)) {
        current->process->is_done = true;
        current->process->exit_status = status;
    }

    printf("%s: exit(%d)\n", current->name, status);
    thread_exit();
}

int wait (pid_t pid)
{
    return process_wait(pid);
}

pid_t exec (const char* cmd_line)
{
    //Attempt to create new process
    pid_t pid = (pid_t)process_execute(cmd_line);
    if (pid == TID_ERROR)
        return -1;

    //Busy wait until process is done loading
    struct process* process = get_child(pid);
    while ((get_child(pid)) && get_child(pid)->load_state == LOAD_PENDING);

    //Fail gracefully... unsuccessful load
    if (process->load_state != LOAD_SUCCESS)
        return -1;

    return pid;
}

int write (int fd, const void* buffer, unsigned size)
{
    //Write to stdout
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }

    //Error if file isn't open
    struct file_info* f = get_file(fd);
    if (!f) return -1;

    //Do filesys call
    lock_acquire(&file_lock);
    int ret = file_write(f->file, buffer, size);
    lock_release(&file_lock);
    return ret;
}

bool create (const char* file, unsigned initial_size)
{
    //Do filesys call
    lock_acquire(&file_lock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);

    return ret;
}

bool remove (const char* file)
{
    //Do filesys call
    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);

    return ret;
}

int read (int fd, void* buffer, unsigned size)
{
    //Read from stdin
    if (fd == STDIN_FILENO) {
        unsigned i;
        uint8_t* buf = (uint8_t*)buffer;
        for (i = 0; i < size; ++i)
            buf[i] = input_getc();
        return size;
    }

    //Fail if file is not open
    struct file_info* f = get_file(fd);
    if (!f) return -1;

    //Do filesys call
    lock_acquire(&file_lock);
    int ret = file_read(f->file, buffer, size);
    lock_release(&file_lock);
    return ret;
}

int filesize (int fd)
{
    //Fail if file is not open
    struct file_info* f = get_file(fd);
    if (!f) return -1;

    //Do filesys call
    lock_acquire(&file_lock);
    int ret = file_length(f->file);
    lock_release(&file_lock);
    return ret;
}

void seek (int fd, unsigned position)
{
    //Fail if file is not open
    struct file_info* f = get_file(fd);
    if (!f) return;

    //Do filesys call
    lock_acquire(&file_lock);
    file_seek(f->file, position);
    lock_release(&file_lock);
}

unsigned tell (int fd)
{
    //Fail if file is not open
    struct file_info* f = get_file(fd);
    if (!f) return -1;

    //Do filesys call
    lock_acquire(&file_lock);
    unsigned ret = (unsigned)file_tell(f->file);
    lock_release(&file_lock);
    return ret;
}

int open (const char* file)
{
    //Do filesys call
    lock_acquire(&file_lock);
    int ret = process_file(file);
    lock_release(&file_lock);

    return ret;
}

void close (int fd)
{
    //Do filesys call
    lock_acquire(&file_lock);
    close_file(fd);
    lock_release(&file_lock);
}

void close_all_files (struct thread* t)
{
    struct list_elem* e = list_begin(&t->file_list);
    while (e != list_end(&t->file_list))
    {
        struct list_elem* next = e->next;
        struct file_info* f = list_entry(e, struct file_info, felem);
        close_file(f->fd);
        e = next;
    }
}

void close_file (int fd)
{
    //Fail if not open
    struct file_info* f = get_file(fd);
    if (!f) return;

    //Free resources
    list_remove(&f->felem);
    file_close(f->file);
    free(f);
}

int process_file (const char* filename)
{
    //Fail if can't open
    struct file* file = filesys_open(filename);
    if (!file) return -1;

    //Allocate resources and add to file_list
    struct thread* current = thread_current();
    struct file_info* f = malloc(sizeof(struct file_info));
    f->file = file;
    f->fd = current->fd;
    ++current->fd;
    list_push_back(&current->file_list, &f->felem);

    return f->fd;
}

//Gets file from file_list by fd
struct file_info* get_file (int fd)
{
    struct list_elem* e;
    struct thread* current = thread_current();

    for (e = list_begin(&current->file_list); e != list_end(&current->file_list);
         e = list_next(e))
    {
        struct file_info* f = list_entry(e, struct file_info, felem);
        if (f->fd == fd)
            return f;
    }
    return NULL;
}

//Cleanup files and children from process
//Used by process_exit to free all owned resources.
void process_cleanup (struct thread* t)
{
    close_all_files(t);

    struct list_elem* e = list_begin(&t->child_list);
    while (e != list_end(&t->child_list))
    {
        struct list_elem* next = e->next;
        struct process* p = list_entry(e, struct process, cpelem);
        list_remove(&p->cpelem);
        free(p);
        e = next;
    }
}

int get_arg(struct intr_frame *f, int i)
{
    int* arg = (int*)f->esp + 1 + i;
    test_bad_address((const void*)arg);
    return *arg;
}

void fill_args(struct intr_frame *f, int* args, int numArgs)
{
    int i;
    for (i = 0; i < numArgs; ++i)
        args[i] = get_arg(f, i);
}

void test_bad_address (const void* addr)
{
    //Validate user address
    if (!is_user_vaddr(addr))
        exit(-1);

    //Validate unmapped
    kptr(addr);
}

//Get unmapped. Fail if unavailable
void* kptr (const void* addr)
{
    if (!is_user_vaddr((const void*)addr))
        exit(-1);
    void* kptr = pagedir_get_page(thread_current()->pagedir, addr);
    if (!kptr)
        exit(-1);
    return kptr;
}


