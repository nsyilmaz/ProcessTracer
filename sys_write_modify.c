#include "defs.h"
#include "util.h"
#include "sys_write_modify.h"


void sys_write_modify(pid_t forked_process, struct user_regs_struct* regs){

	unsigned char buffer[BUFFER_SIZE];
	long addr;

	printf("SYS_write \n");
	printf("Size: %li\n", regs->eax );
	addr = regs->ecx;

	// if legitimate 
	if (regs->eax > 0){
		umoven_peekdata(forked_process, addr, regs->eax, buffer );
		buffer[regs->eax] = '\0';
		if(strlen(buffer)){
			printf("%s\n",buffer);
			if(strstr(buffer, "aaaa")){
				sprintf(buffer, "%s", "hede hod.kajsDN.Kjdn.kjASND.kjnsd.kjNSD.Kjnds.kjaND.KJns.dkjna.KJosenol\0");
				putdata(forked_process, addr, buffer, strlen(buffer));
				ptrace(PTRACE_GETREGS, forked_process, NULL, regs); 
				regs->eax=strlen(buffer);
				ptrace(PTRACE_SETREGS, forked_process, NULL, regs);
			}
		}
	}
	printf("---\n");

}
