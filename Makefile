CFLAGS=-g

CC=gcc

LIBS = -lssl -lcrypto

PROG = ncs.out

all: $(PROG)

ncs.out: generic.h encrypt.o hashfun.c readwrite.c main.c
	$(CC) $(CFLAGS) -o ncs.out encrypt.o hashfun.c readwrite.c main.c $(LIBS)

encrypt.o: encrypt.h encrypt.c
	$(CC) $(CFLAGS) -c encrypt.h encrypt.c $(LIBS)

clean:
	rm $(PROG) *.o *.gch