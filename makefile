CC      = gcc
CFILES  = main_server.c
BFILES  = main_server
OFILES  = util.o request_handler.o process_list.o ptrace.o
CFLAGS  = -g -lpthread


$(BFILES):$(OFILES)

all: $(BFILES)

clean:
	rm -rf $(BFILES) $(OFILES) *.c~

