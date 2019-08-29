#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

struct sys_readReturn{
  char *data;
  int length;
};
void sys_read(pid_t,struct user_regs_struct*,struct sys_readReturn*);
