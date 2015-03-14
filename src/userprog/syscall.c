#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"



static void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
int wait (pid_t pid);
int filesize (int fd);
int read (int fd, void* buffer, unsigned length);
int write (int fd, const void* buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
pid_t exec (const char* cmd_line);
bool create (const char* file, unsigned initial_size);
bool remove (const char* file);
int open (const char* file);
void close (int fd);

struct lock file_lock;

// Info for file in threads files
struct file_info 
{
    int fid;                    // file descriptor integer
    struct list_elem elem;      //element to store in the files
    struct file *filep;         //points to file
};

void fill_args(struct intr_frame *f, int* args, int numArgs);
void *kptr (const void* addr);
int process_file (const char* file); 
void close_file (int fd);
bool file_exists (struct file *file_ptr);
bool file_info_exists (struct file_info *file_ptr);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
    if (!is_user_vaddr(f->esp))
            exit(-1);
        kptr(f->esp);

    //Arguments passed to syscall, can only have 3 at most
    int syscall_args[3]; 
    int *num_syscall = (int*)f->esp;
    void *kp = NULL;
    bool func_done = false;

    if (*num_syscall == SYS_HALT)
    {
        halt ();
        func_done = true;
    }

    if(func_done){
        return;
    }

    fill_args (f, &syscall_args[0], 1);
    switch (*num_syscall) 
    {
        case SYS_EXIT:
            exit(syscall_args[0]);
            func_done = true;
            break;
        
        case SYS_EXEC:
            kp = kptr((const void*)syscall_args[0]);
            f->eax = exec((const char*)kp);
            func_done = true;
            break;
        
        case SYS_WAIT:
            f->eax = wait(syscall_args[0]);
            func_done = true;
            break;

        case SYS_REMOVE:
            kp = kptr((const void*)syscall_args[0]);
            f->eax = remove((const char*)kp);
            func_done = true;
            break;
        
        case SYS_OPEN:
            kp = kptr((const void*)syscall_args[0]);
            f->eax = open((const char*)kp);
            func_done = true;
            break;
        
        case SYS_FILESIZE:
            f->eax = filesize(syscall_args[0]);
            func_done = true;
            break;

        case SYS_TELL:
            f->eax = tell(syscall_args[0]);
            func_done = true;
            break;
        
        case SYS_CLOSE:
            close (syscall_args[0]);
            func_done = true;
            break;
        
        default:
            break; 
    }

    if(func_done){
        return;
    }

    fill_args (f, &syscall_args[0], 2);
    switch (*num_syscall)
    {
        case SYS_CREATE:
            kp = kptr((const void*)syscall_args[0]);
            f->eax = create((const char*)kp, (unsigned)syscall_args[1]);
            func_done = true;
            break;

        case SYS_SEEK:
            seek(syscall_args[0], (unsigned)syscall_args[1]);
            func_done = true;
            break;

        default:
            break;
    }

    if(func_done){
        return;
    }

    fill_args (f, &syscall_args[0], 3);
    switch (*num_syscall)
    {
        case SYS_READ:
            kp = kptr((const void*)syscall_args[1]);
            f->eax = read(syscall_args[0], kp, (unsigned)syscall_args[2]);
            func_done = true;
            break;

        case SYS_WRITE:
            kp = kptr((const void*)syscall_args[1]);
            f->eax = write(syscall_args[0], (const char*)kp, (unsigned)syscall_args[2]);
            func_done = true;
            break;

        default:
            break;
    }
    if(func_done){
        return;
    }

}

bool
file_exists (struct file *file_ptr)
{
    if (file_ptr != NULL)
    {
        return true;
    }
    else{
        return false;
    }
}



void 
halt (void)
{
    shutdown_power_off();
}

void 
exit (int status)
{
    struct thread *cur = thread_current();
    
    if (get_thread(cur->thread_process->tid)) {
        cur->thread_process->exit_status = status;
        cur->thread_process->is_done = true;
    }

    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

int 
wait (pid_t pid)
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
    struct process_info *process = get_child(pid);
    while ((get_child(pid)) && get_child(pid)->load_state == LOAD_PENDING);

    // if it failed 
    if (process->load_state != LOAD_SUCCESS)
        return -1;

    return pid;
}

bool 
file_info_exists (struct file_info *file_ptr)
{
    if (file_ptr != NULL)
    {
        return true;
    }
    else{
        return false;
    }
}

int
write (int fd, const void *buffer, unsigned size)
{
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }
    struct file_info *f;
    f = NULL;

    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }
    if (!file_info_exists (f)){
        return -1;
    }

    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    int ret = file_write(f->filep, buffer, size);
    lock_release(&file_lock);
    return ret;
    
}

bool 
create (const char* file, unsigned initial_size)
{
    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);

    return ret;
}

bool 
remove (const char* file)
{
    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);

    return ret;
}

int 
read (int fd, void* buffer, unsigned size)
{
    //Read from stdin
    if (fd == STDIN_FILENO) {
        unsigned i;
        uint8_t *buf = (uint8_t*) buffer;
        for (i = 0; i < size; ++i)
            buf[i] = input_getc();
        return size;
    }
    struct file_info *f = NULL;
    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }
    
    if (!file_info_exists (f)){
        return -1;
    }

    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    int ret = file_read(f->filep, buffer, size);
    lock_release(&file_lock);
    return ret;
}

int 
filesize (int fd)
{
    //Fail if file is not open
    struct file_info *f = NULL;
    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }

    if (!file_info_exists (f)){
        return -1;
    }

    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    int ret = file_length(f->filep);
    lock_release(&file_lock);
    return ret;
}

void 
seek (int fd, unsigned position)
{
    //Fail if file is not open
    struct file_info *f = NULL;
    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }

    if (!file_info_exists (f)){
        return;
    }

    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    file_seek(f->filep, position);
    lock_release(&file_lock);
}

void 
close (int fd)
{
    //lock the stack and then use the super helpful filesys call
    if (fd <= 0){
        return;
    }
    lock_acquire(&file_lock);
    //using the filesys call
    close_file(fd);
    lock_release(&file_lock);
}

unsigned 
tell (int fd)
{
    //Fail if file is not open
    struct file_info *f = NULL;
    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }

    if (!file_info_exists (f)){
        return -1;
    }

    //lock the stack and then use the super helpful filesys call
    lock_acquire(&file_lock);
    //using the filesys call
    unsigned ret = (unsigned)file_tell(f->filep);
    lock_release(&file_lock);
    return ret;
}

int 
open (const char *file)
{
    //lock the stack and then use the super helpful filesys call
    if (!file){
        return -1;
    }
    lock_acquire(&file_lock);
    //using the filesys call
    int ret = process_file(file);
    lock_release(&file_lock);

    return ret;
}

void 
close_file (int fd)
{
    //Fail if not open
    struct file_info *f = NULL;
    struct thread* cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
    {
        struct file_info *tmpf = list_entry(e, struct file_info, elem);
        if (tmpf->fid == fd)
        {
            f = tmpf;
            break;
        }
    }

    if (!file_info_exists (f)){
        return;
    }

    list_remove(&f->elem);
    file_close(f->filep);
    free(f);
}

int 
process_file (const char* filename)
{
    //Fail if can't open
    struct file *file = filesys_open(filename);

    if (!file_exists (file)){
        return -1;
    }

    //Allocate resources and add to files
    struct thread* cur = thread_current();
    struct file_info* f = malloc(sizeof(struct file_info));

    if (!file_info_exists (f)){
        return -1;
    }

    f->filep = file;
    f->fid = cur->fid;
    cur->fid = cur->fid +1;

    list_push_back(&cur->files, &f->elem);

    return f->fid;
}

void 
process_cleanup (struct thread* t)
{
    struct list_elem* e = list_begin(&t->files);
    while (e != list_end(&t->files))
    {
        struct list_elem* next = e->next;
        struct file_info* f = list_entry(e, struct file_info, elem);
        close_file(f->fid);
        e = next;
    }

    e = list_begin(&t->children);
    while (e != list_end(&t->children))
    {
        struct list_elem* next = e->next;
        struct process_info *pros = list_entry(e, struct process_info, list_ele);
        list_remove(&pros->list_ele);
        free(pros);
        e = next;
    }
}

void 
fill_args(struct intr_frame *f, int* args, int numArgs)
{
    int i;
    for (i = 0; i < numArgs; ++i)
    {
        int *arg = (int*)f->esp + 1 + i;
        if (!is_user_vaddr(arg))
            exit(-1);
        kptr(arg);
        args[i] = *arg;
    }
}

//Get unmapped. Fail if unavailable
void * 
kptr (const void* addr)
{
    if (!is_user_vaddr((const void*)addr))
        exit(-1);
    void* kptr = pagedir_get_page(thread_current()->pagedir, addr);
    if (!kptr)
        exit(-1);
    return kptr;
}




