#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>


struct sys_closeReturn{
  int fileDescriptor;
};

void sys_close(pid_t process,struct user_regs_struct* structRegs,struct sys_closeReturn* closeReturn);
