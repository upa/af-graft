CC = gcc 
INCLUDE := -I../include/
CFLAGS := -g -Wall $(INCLUDE)

PROGNAME = bind-test setsockopt-test


all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm $(PROGNAME)
