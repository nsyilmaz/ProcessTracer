#include "defs.h"
#include "util.h"
#include "sys_send.h"


void sys_send(pid_t forked_process, struct user_regs_struct* regs){

	unsigned char buffer[BUFFER_SIZE];
	long addr;
	int i;
	printf("SYS_send \n");
	printf("Size: %li\n", regs->eax );
	addr = regs->ecx;

	if (regs->eax > 0){
		get_args(forked_process, addr, 4, buffer);
		for (i=0; i < regs->eax; i++){
			printf("%c", buffer[i]);
		}
	}
	printf("---\n");

}
