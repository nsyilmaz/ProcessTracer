#include "util.h"
#include "sys_close_modify.h"
#include "defs.h"

void sys_closeModify(pid_t process,struct user_regs_struct* structRegs,struct sys_closeModify* sys_closeModify){
        structRegs->rdi = sys_closeModify->fileDescriptor;
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
}
