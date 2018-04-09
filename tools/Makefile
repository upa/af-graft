CC = gcc 
INCLUDE := -I../include/ -I../iproute2-4.10.0/include/
CFLAGS := -g -Wall $(INCLUDE)
LDL_FLAGS := -fPIC -shared -ldl
LIB := libnetlink.o libgenl.o

PROGNAME = libgraft-hijack.so


all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) $(LDL_FLAGS) -c $<

libgraft-hijack.so: libgraft-hijack.c $(LIB)
	$(CC) $< $(CFLAGS) $(LDL_FLAGS) $(LIB) -o $@
	cp $@ libgrwrap.so

clean:
	rm $(PROGNAME) $(LIB)
