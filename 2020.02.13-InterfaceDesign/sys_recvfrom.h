#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

struct sys_recvfromReturn{
    char *data;
    int length;
};

void sys_recvfrom(pid_t,struct user_regs_struct*,struct sys_recvfromReturn*);
