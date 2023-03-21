debug: compil_main
	valgrind --track-origins=yes ./encryption

encryption: encryption.o
	./encryption.o

encryption.o: src/encryption.c
	gcc -Wall -o encryption.o src/encryption.c

clean:
	rm -f encryption.o