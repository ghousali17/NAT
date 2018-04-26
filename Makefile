CC = g++
CFLAGS = -Wall
LIB = -lnfnetlink -lnetfilter_queue -lpthread

all:
	$(CC) $(CFLAGS) nat.c checksum.c -o nat $(LIB)

clean:
	@rm -f nat
