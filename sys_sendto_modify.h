#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

struct sys_sendtoModify{
    char *data;
    int length;
};

void sys_sendtoModify(pid_t,struct user_regs_struct*,struct sys_sendtoModify*);
