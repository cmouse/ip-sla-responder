CONFIGFILE=/etc/responder.conf
LD=$(CC)
CFLAGS=-W -Wall -Wno-unused -g -O2 -DCONFIGFILE="\"$(CONFIGFILE)\""
LDFLAGS=-g
OBJECTS=utils.o pak.o ether.o ip.o ip6.o icmp4.o icmp6.o arp.o udp4.o udp6.o junos.o cisco.o
BINARIES=responder
LIBS=-lrt -lpcap

.PHONY: all clean

all: $(BINARIES)

$(OBJECTS): responder.h

responder: $(OBJECTS) main.o
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) main.o $(LIBS)

responder-test: $(OBJECTS) test-main.o
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) test-main.o $(LIBS)

test: responder-test
	./$<

check: test

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf responder responder-test *.o *.so

