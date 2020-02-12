CC      = gcc
CFILES  = main_server.c
BFILES  = main_server
OFILES  = util.o request_handler.o process_list.o ptrace.o sys_write.o sys_open.o sys_read.o sys_close.o sys_sendto.o sys_recvfrom.o sys_connect.o sys_accept.o sys_read_modify.o sys_write_modify.o sys_open_modify.o sys_recvfrom_modify.o sys_sendto_modify.o sys_close_modify.o sys_connect_modify.o sys_accept_modify.o
CFLAGS  = -g -pthread


$(BFILES):$(OFILES)

all: $(BFILES)
	echo 0 > /proc/sys/kernel/yama/ptrace_scope

clean:
	rm -rf $(BFILES) $(OFILES) *.c~

