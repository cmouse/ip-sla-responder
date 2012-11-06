CC=gcc
CFLAGS=-W -Wall -Wno-unused -g -O0
LD=gcc
LDFLAGS=-g
BINARY=responder
OBJECTS=responder.o
LIBS=-lrt -lpcap

.PHONY: all clean

$(BINARY): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(BINARY) $(OBJECTS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BINARY) *.o *.so

