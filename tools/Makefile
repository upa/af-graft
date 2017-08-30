CC = gcc 
INCLUDE := -I../include/ -I../iproute2-4.10.0/include/
CFLAGS := -g -Wall $(INCLUDE)
LDL_FLAGS := -fPIC -shared -ldl
LIB := libnetlink.o libgenl.o

PROGNAME = libgrwrap.so


all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) $(LDL_FLAGS) -c $<

libgrwrap.so: libgrwrap.c $(LIB)
	$(CC) $< $(CFLAGS) $(LDL_FLAGS) $(LIB) -o $@

clean:
	rm $(PROGNAME) $(LIB)
