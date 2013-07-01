CC=gcc
CFLAGS=-W -Wall -Wno-unused -g -O0 -mtune=native -march=native -DHAS_VLAN=1
LD=gcc
LDFLAGS=-g
OBJECTS=pak.o ether.o ip.o ip6.o icmp.o arp.o nd.o udp4.o junos.o cisco.o utils.o
BINARIES=responder
LIBS=-lrt -lpcap

.PHONY: all clean

all: $(BINARIES)

responder: $(OBJECTS) main.o
	$(LD) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJECTS) main.o $(LIBS)

responder-test: $(OBJECTS) test-main.o
	$(LD) $(LDFLAGS) $(CFLAGS) -o $@ -Wl,--wrap,send responder-test.c responder.c $(LIBS)

test: responder-test
	./$<

check: test

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf responder responder-test *.o *.so

