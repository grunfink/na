PREFIX=/usr/local

na: na.h na.o na-sodium.o
	$(CC) -g -Wall na.o na-sodium.o `pkg-config --libs libsodium` -o $@

na.o: na.c na.h
	$(CC) -g -Wall $< -c

na-sodium.o: na-sodium.c na.h
	$(CC) -g -Wall `pkg-config --cflags libsodium` $< -c

install:
	install -m 755 na $(PREFIX)/bin/na

uninstall:
	rm -f $(PREFIX)/bin/na

dist: clean
	cd .. && tar czvf na/na.tar.gz na/*

clean:
	rm -f na *.tar.gz *.asc *.o
