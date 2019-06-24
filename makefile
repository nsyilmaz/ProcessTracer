CC      = gcc
CFILES  = main_server.c
BFILES  = main_server
OFILES  = util.o request_handler.o process_list.o ptrace.o
CFLAGS  = -g -lpthread


$(BFILES):$(OFILES)

all: $(BFILES)
	echo 0 > /proc/sys/kernel/yama/ptrace_scope


clean:
	rm -rf $(BFILES) $(OFILES) *.c~

