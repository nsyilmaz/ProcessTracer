CC      = gcc
CFILES  = main_server.c
BFILES  = main_server
OFILES  = util.o request_handler.o process_list.o ptrace.o
CFLAGS  = -g -lpthread


$(BFILES):$(OFILES)

all: $(BFILES)
	echo 0 > /proc/sys/kernel/yama/ptrace_scope

<<<<<<< HEAD

=======
>>>>>>> ab78f480209ece04ce8662bf45ce3672a5ad1d40
clean:
	rm -rf $(BFILES) $(OFILES) *.c~

