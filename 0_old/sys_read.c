#include "defs.h"
#include "util.h"
#include "sys_read.h"


void sys_read(pid_t forked_process, struct user_regs_struct* regs){

	unsigned char buffer[BUFFER_SIZE];
	long addr;

	printf("SYS_read \n");
	printf("Size: %li\n", regs->eax );
	addr = regs->ecx;

	// if legitimate
	if (regs->eax > 0){
		umoven_peekdata(forked_process, addr, regs->eax, buffer );
		buffer[regs->eax] = '\0';
		if(strlen(buffer)){
			printf("%s\n",buffer);
		}
	}
	printf("---\n");

}
