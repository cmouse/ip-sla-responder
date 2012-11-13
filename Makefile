CC=gcc
CFLAGS=-W -Wall -Wno-unused -g -O0 -mtune=native -march=native -DHAS_VLAN=1
LD=gcc
LDFLAGS=-g
BINARIES=responder-test responder
LIBS=-lrt -lpcap

.PHONY: all clean

all: $(BINARIES)

responder: responder-main.o
	$(LD) $(LDFLAGS) -o $@ $< $(LIBS)

responder-test: responder-test.o
	$(LD) $(LDFLAGS) -o $@ $< $(LIBS)

test: test.o
	$(LD) $(LDFLAGS) -o $@ $< $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BINARIES) *.o *.so

