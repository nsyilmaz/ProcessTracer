CC      = gcc
CFILES  = trace.c
BFILES  = trace
OFILES  = util.o sys_read.o sys_open.o sys_write.o sys_close.o sys_send.o sys_recv.o sys_read_modify.o sys_write_modify.o
CFLAGS  = -g


$(BFILES):$(OFILES)

all: $(BFILES)

clean:
	rm -rf $(BFILES) $(OFILES) *.c~


