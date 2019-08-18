#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

struct sys_openReturn{
  char* fileName;
  int length;
};

void sys_open(pid_t,struct user_regs_struct*,struct sys_openReturn*);
