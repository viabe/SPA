CC := gcc
CFLAGS := -Wall -Werror
LDFLAGS := -L. -lgnspa -lssl -lcrypto

all: libgnspa.so client

libgnspa.so: gnspa.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

gnspa.o: gnspa.c gnspa.h
	$(CC) $(CFLAGS) -c -fpic $< -o $@

client: client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o libgnspa.so client
