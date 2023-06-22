CC := gcc
CFLAGS := -Wall -Werror
LDFLAGS := -L./bin -lgnspa -lssl -lcrypto -loath
BINDIR := bin

all: $(BINDIR)/libgnspa.so $(BINDIR)/client

$(BINDIR)/libgnspa.so: gnspa.o | $(BINDIR)
	$(CC) $(LDFLAGS) -shared -o $@ $<

gnspa.o: gnspa.c gnspa.h
	$(CC) $(CFLAGS) -c -fpic $< -o $@

$(BINDIR)/client: client.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f *.o $(BINDIR)/libgnspa.so $(BINDIR)/client
