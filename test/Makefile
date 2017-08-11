CC = gcc 
CFLAGS := -g -Wall
INCLUDE := -I../include/

PROGNAME = bind-test



all: $(PROGNAME)

bind-test: bind-test.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	rm $(PROGNAME)
