CC = gcc 
INCLUDE := -I../include/ -I../iproute2-4.10.0/include/
CFLAGS := -g -Wall $(INCLUDE) -DHAVE_IPV6
LDL_FLAGS := -fPIC -shared -ldl
LIB := libnetlink.o libgenl.o patricia.o

PROGNAME = libgraft-hijack.so libgraft-convert.so


all: $(PROGNAME)

.c.o:
	$(CC) $(INCLUDE) $(LDL_FLAGS) $(CFLAGS) -c $<

libgraft-hijack.so: libgraft-hijack.c $(LIB)
	$(CC) $< $(CFLAGS) $(LDL_FLAGS) $(LIB) -o $@
	cp $@ libgrwrap.so

libgraft-convert.so: libgraft-convert.c $(LIB)
	$(CC) $< $(CFLAGS) $(LDL_FLAGS) $(LIB) -o $@

install: all
	install -m 644 -D ./libgraft-convert.so	/usr/local/lib/
	install -m 755 -D ./graft /usr/local/bin/

clean:
	rm $(PROGNAME) $(LIB)
