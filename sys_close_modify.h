#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

struct sys_closeModify{
    int fileDescriptor;
};

void sys_closeModify(pid_t,struct user_regs_struct*,struct sys_closeModify*);
