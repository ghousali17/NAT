all:
	g++ -o nftest nftest.c checksum.c -lnfnetlink -lnetfilter_queue -lpthread
checksum:
	g++ checksum.o checksum.c
clean:
	@rm -f nftest
