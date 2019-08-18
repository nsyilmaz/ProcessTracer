CC      = gcc
CFILES  = main_server.c
BFILES  = main_server
OFILES  = util.o request_handler.o process_list.o ptrace.o sys_write.o sys_open.o sys_read.o sys_close.o
CFLAGS  = -g -pthread


$(BFILES):$(OFILES)

all: $(BFILES)
	echo 0 > /proc/sys/kernel/yama/ptrace_scope

clean:
	rm -rf $(BFILES) $(OFILES) *.c~

