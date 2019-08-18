#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <pthread.h>
#include <time.h>
#include "kernel_types.h"
#define _GNU_SOURCE



#ifndef HAVE_PROCESS_VM_READV
/*
 * Need to do this since process_vm_readv() is not yet available in libc.
 * When libc is updated, only "static bool process_vm_readv_not_supported"
 * line remains.
 * The name is different to avoid potential collision with OS headers.
 */
static ssize_t strace_process_vm_readv(pid_t pid,
                 const struct iovec *lvec,
                 unsigned long liovcnt,
                 const struct iovec *rvec,
                 unsigned long riovcnt,
                 unsigned long flags)
{
        return syscall(__NR_process_vm_readv,
                       (long) pid, lvec, liovcnt, rvec, riovcnt, flags);
}
# define process_vm_readv strace_process_vm_readv
#endif /* !HAVE_PROCESS_VM_READV */


int umovestr_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, void *laddr);


int umoven_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, char *laddr);

int execvArraySize(char* cursor);


const char *syscallName(long call);

extern char responseBuffer[];
extern char end[];
extern char responseHeader[];
extern char responseEnd[];

struct process{
  char *pid;
  char *ppid;
  char *user;
  char *name;
  char *cmdline;
};

struct processList{
int length;
struct process* array;
};

struct syscallRegs{
  char* data;
  struct user_regs_struct* regs;
  int entry_exit_flag;
};

struct syscallList{
    int length;
    struct syscallRegs* array;
};


extern struct processList pList;

extern struct syscallList sList;

extern int returnForRequestHandler;

extern int processListStateFlag;

extern int flagForNext;

extern pid_t traced_process;

extern pthread_t threadAttach;

extern pthread_t threadFork;

extern int isStartedPtrace;

extern char* pathForPtrace;

int ishex(int x);

int decode(const char *s, char *dec);

int stringSplit(char* c);

extern char tableStart[];

extern char tableEnd[];

int checkInt(char buffer[]);

int umoven_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, char *laddr);

void cats(char **str, const char *str2);

struct process* searchByPID(char *pid);

void getdata(pid_t child, long addr,char *str, int len);
