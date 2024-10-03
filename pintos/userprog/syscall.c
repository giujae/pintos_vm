#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/** #Project 2: System Call */
typedef int pid_t;
#include <string.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"

/* Project 3: Virtual Memory */
#include "include/vm/file.h"

struct lock filesys_lock;
/** -----------------------  */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
#ifdef VM
	thread_current()->stack_pointer = f->rsp;
#endif
switch (f->R.rax)
	{
	case SYS_HALT:
		halt_syscall();
		break;
	case SYS_EXIT:
		exit_syscall(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax =fork_syscall(f->R.rdi);
		break;
	case SYS_EXEC:
		if (exec_syscall(f->R.rdi) == -1)
        {
            exit_syscall(-1);
        }
		break;
	case SYS_WAIT:
		f->R.rax =wait_syscall(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create_syscall(f->R.rdi,f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove_syscall(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open_syscall(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize_syscall(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read_syscall(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write_syscall(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek_syscall(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell_syscall(f->R.rdi);
		break;
	case SYS_CLOSE:
		close_syscall(f->R.rdi);
		break;
#ifdef VM
	case SYS_MMAP:
		f->R.rax = mmap_syscall(f->R.rdi,f->R.rsi,f->R.rdx,f->R.r10,f->R.r8);
		break;
	case SYS_MUNMAP:
		munmap_syscall(f->R.rdi);
		break;
#endif
	default:
		exit_syscall(-1);
		break;
	}
}

// ================================= utils =================================

#ifndef VM
/** #Project 2: System Call */
void check_address(void *addr) {
    thread_t *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
        exit_syscall(-1);
}
#else
/** #Project 3: Anonymous Page */
struct page *check_address(void *addr) {
    THREAD *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL)
        exit_syscall(-1);

    return spt_find_page(&curr->spt, addr);
}

/** Project 3: Memory Mapped Files - 버퍼 유효성 검사 */
void check_valid_buffer(void *buffer, size_t size, bool writable) {
    for (size_t i = 0; i < size; i++) {
        /* buffer가 spt에 존재하는지 검사 */
        struct page *page = check_address(buffer + i);

        if (!page || (writable && !(page->writable)))
            exit_syscall(-1);
    }
}
#endif


// ================================= system call functions =================================
void halt_syscall(){
	power_off();
}

void exit_syscall(int status){
	struct thread *cur = thread_current();
	
	cur->exit_status = status;

	printf("%s: exit(%d)\n", cur->name, cur->exit_status);

	thread_exit();
}


pid_t fork_syscall(const char *thread_name){
	check_address(thread_name);

	return process_fork(thread_name,NULL);
}

int exec_syscall(const char *cmd_line){
	check_address(cmd_line);

	off_t size = strlen(cmd_line)+1;
	char *cmd_copy = palloc_get_page(PAL_ZERO);

	if(cmd_copy == NULL){
		return -1;
	}

	memcpy(cmd_copy,cmd_line,size);

	return process_exec(cmd_copy);
}

int wait_syscall(pid_t tid){
	return process_wait(tid);
}

bool create_syscall(const char *file, unsigned initial_size){
	check_address(file);

	lock_acquire(&filesys_lock);
	bool success = filesys_create(file,initial_size);
	lock_release(&filesys_lock);

	return success;
}

bool remove_syscall(const char *file){
	check_address(file);

	lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	lock_release(&filesys_lock);

	return success;
}

int open_syscall(const char *file){
	check_address(file);

	lock_acquire(&filesys_lock);
	struct file *new_file = filesys_open(file);

	if(new_file==NULL){
		goto err;
	}

	int fd = process_add_file(new_file);

	if(fd == -1){
		file_close(new_file);
	}

	lock_release(&filesys_lock);
	return fd;

err:
	lock_release(&filesys_lock);
	return -1;
}

int filesize_syscall(int fd){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL)
		return -1;

	return file_length(file);
}

int read_syscall(int fd, void *buffer, unsigned length){

#ifdef VM
    check_valid_buffer(buffer, length, true);
#endif
    check_address(buffer);

    THREAD *curr = thread_current();
	struct file *file = get_file_from_fd(fd);

    if (file == NULL || file == STDOUT || file == STDERR)  // 빈 파일, stdout, stderr를 읽으려고 할 경우
		return -1;

    if (file == STDIN) {  // stdin -> console로 직접 입력
        int i = 0;        // 쓰레기 값 return 방지
		char c; 
		unsigned char *buf = buffer;

        for (; i < length; i++) {
			c = input_getc();
			*buf++ = c;
            if (c == '\0')
				break;
		}

		return i;
	}

    // 그 외의 경우
    lock_acquire(&filesys_lock);
    off_t bytes = file_read(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes;
}

int write_syscall(int fd, const void *buffer, unsigned length){
#ifdef VM
    check_valid_buffer(buffer, length, true);
#endif
    check_address(buffer);

	lock_acquire(&filesys_lock);
	struct thread *curr = thread_current();
	off_t bytes = -1;

	struct file *file = get_file_from_fd(fd);

	if(file == STDIN || file == NULL)
		goto done;

	if(file == STDOUT || file == STDERR){
		putbuf(buffer, length);
		bytes = length;
		goto done;
	}
	
	bytes = file_write(file,buffer,length);

done:
	lock_release(&filesys_lock);
	return bytes;
}

void seek_syscall(int fd, unsigned position){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL || (file>=STDIN &&file<=STDERR))
		return;

	file_seek(file,position);
}

int tell_syscall(int fd){
	struct file *file = get_file_from_fd(fd);

	if(file == NULL || (file >=STDIN && file<=STDERR))
		return -1;
	
	return file_tell(file);
}

void close_syscall(int fd){
	struct thread *curr = thread_current();
	struct file *file = get_file_from_fd(fd);

	if(file == NULL)
		goto done;

	remove_file_in_fd_table(fd);

	if(file >= STDIN && file <= STDERR){
		file = 0;
		goto done;
	}
	
	if(file->dup_count == 0){
		file_close(file);
	}else{
		file->dup_count--;
	}
done:
	return;
}

void *mmap_syscall(void *addr, size_t length, int writable, int fd, off_t offset){
	struct supplemental_page_table spt = thread_current()->spt;
    if (!addr || pg_round_down(addr) != addr || is_kernel_vaddr(addr) || is_kernel_vaddr(addr + length))
        return NULL;

    if (offset != pg_round_down(offset) || offset % PGSIZE != 0)
        return NULL;

    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

    struct file *file = get_file_from_fd(fd);

    if ((file >= STDIN && file <= STDERR) || file == NULL)
        return NULL;

    if (file_length(file) == 0 || (long)length <= 0)
        return NULL;

    return do_mmap(addr, length, writable, file, offset);
}

void munmap_syscall(void *addr){
	do_munmap(addr);

	return;
}
