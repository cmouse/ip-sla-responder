CC=gcc
CFLAGS=-W -Wall -Wno-unused -g -O0 -mtune=native -march=native -DHAS_VLAN=1
LD=gcc
LDFLAGS=-g
BINARIES=responder
LIBS=-lrt -lpcap

.PHONY: all clean

all: $(BINARIES)

responder: responder-main.o responder.c
	$(LD) $(LDFLAGS) -o $@ responder-main.o $(LIBS)

responder-test: responder-test.o responder.c
	$(LD) $(LDFLAGS) -o $@ responder-test.o $(LIBS)

test: responder-test
	./responder-test

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf responder responder-test *.o *.so

