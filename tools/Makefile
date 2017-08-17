CC = gcc 
INCLUDE := -I../include/
CFLAGS := -g -Wall $(INCLUDE)
LDL_FLAGS := -fPIC -shared -ldl

PROGNAME = libgrwrap.so


all: $(PROGNAME)

libgrwrap.so: libgrwrap.c
	$(CC) $< $(CFLAGS) $(LDL_FLAGS) -o $@

clean:
	rm $(PROGNAME)
