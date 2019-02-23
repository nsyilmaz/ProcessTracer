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

int umovestr_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, void *laddr);


int umoven_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, char *laddr);


const char *syscallName(long call);

void get_args(pid_t process, long addr, int len, unsigned char *buf);

void getdata(pid_t child, long addr,char *str, int len);

void putdata(pid_t child, long addr, char *str, int len);
